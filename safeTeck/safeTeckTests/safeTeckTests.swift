//
//  safeTeckTests.swift
//  safeTeckTests
//
//  Created by Al Stark on 17.10.2023.
//

import XCTest
@testable import safeTeck

final class safeTeckTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() async throws {
        // Создаём массив из 100 рандомных строк
        
        let inputStrings = (0..<100).map { _ in UUID().uuidString }
        let cryptor = Cryptor()
        // Шифруем каждую строку и сохраняем
        for string in inputStrings {
            try await Cryptor.store(string: string)
        }
        // Получаем расшифрованные строки
        let storedStrings = await cryptor.strings

        // Проверяем, что исходный массив и расшифрованный массив совпадают
        XCTAssertEqual(storedStrings, inputStrings)
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
