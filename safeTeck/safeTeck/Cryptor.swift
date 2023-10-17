//
//  Cryptor.swift
//  safeTeck
//
//  Created by Al Stark on 17.10.2023.
//

import Foundation
import CryptoKit
import Security
import CommonCrypto
import CoreData


public final class Cryptor {
    private static var privateKey: P256.KeyAgreement.PrivateKey?
    private static var context: NSManagedObjectContext?
    private static let keychainPrivateKeyTag = "com.safeApp.privatekey"
    
    //     Возвращает список расшифрованных записей из базы данных
    public var strings: [String] {
        get async {
            guard let context = Cryptor.context else {
                print("Core Data context is nil")
                return []
            }
            let fetchRequest: NSFetchRequest<EncryptedStringEntity> = EncryptedStringEntity.fetchRequest()
            
            do {
                let encryptedEntities = try context.fetch(fetchRequest)
                return try encryptedEntities.compactMap { entity in
                    if let encryptedData = entity.encryptedData {
                        return try Cryptor.decryptData(encryptedData, using: Cryptor.privateKey!)
                    } else {
                        return nil
                    }
                }
            } catch {
                print("Failed to fetch encrypted strings: \(error)")
                return []
            }
        }
    }
    
    public init() {
        setupCoreData()
        
        do {
            if let retrievedKey = try Cryptor.retrievePrivateKeyFromKeychain() {
                Cryptor.privateKey = retrievedKey
            }
        } catch {
            print("Failed to retrieve the private key from the keychain: \(error)")
        }
    }
    
    private func setupCoreData() {
        let modelName = "ModelCoreData"
        let bundle = Bundle(for: type(of: self))
        
        guard let modelURL = bundle.url(forResource: modelName, withExtension: "momd") else {
            fatalError("Failed to find model URL")
        }
        
        guard let mom = NSManagedObjectModel(contentsOf: modelURL) else {
            fatalError("Failed to create model from \(modelURL)")
        }
        
        let container = NSPersistentContainer(name: modelName, managedObjectModel: mom)
        container.loadPersistentStores { storeDescription, error in
            if let error = error {
                fatalError("Failed to load persistent stores: \(error)")
            }
            Cryptor.context = container.viewContext
        }
    }
    
    /// Шифрует переданную строку и сохраняет её в базу данных
    public static func store(string: String) async throws {
        guard let context = context else {
            return
        }
        
        if privateKey == nil {
            privateKey = P256.KeyAgreement.PrivateKey()
            try storePrivateKeyInKeychain(privateKey: privateKey!)
        }
        
        let encryptedString = try encryptString(string, using: privateKey!)
        
        let encryptedEntity = EncryptedStringEntity(context: context)
        encryptedEntity.encryptedData = encryptedString
        
        do {
            try context.save()
        } catch {
            print("Failed to save encrypted string: \(error)")
        }
    }
    
    
    private static func encryptString(_ inputString: String, using privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        let inputData = Data(inputString.utf8)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
        
        let encryptedData = try AES.GCM.seal(inputData, using: SymmetricKey(data: sharedSecret))
        
        return encryptedData.combined ?? Data()
    }
    
    private static func decryptData(_ data: Data, using privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
        let box = try AES.GCM.SealedBox(combined: data)
        let decryptSealedBox = try! AES.GCM.open(box, using: SymmetricKey(data: sharedSecret))
        return String(data: decryptSealedBox, encoding: .utf8)!
    }
    
    private static func storePrivateKeyInKeychain(privateKey: P256.KeyAgreement.PrivateKey) throws {
        let keyData = privateKey.rawRepresentation
        
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keychainPrivateKeyTag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecValueData as String: keyData]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }
    }
    
    private static func retrievePrivateKeyFromKeychain() throws -> P256.KeyAgreement.PrivateKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keychainPrivateKeyTag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecReturnData as String: kCFBooleanTrue!,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }
        
        guard let keyData = item as? Data,
              let privateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: keyData) else {
            return nil
        }
        
        return privateKey
    }
}
