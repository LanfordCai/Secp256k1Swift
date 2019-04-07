import XCTest

#if !canImport(ObjectiveC)
    public func allTests() -> [XCTestCaseEntry] {
        return [
            testCase(Secp256k1SwiftTests.allTests),
        ]
    }
#endif
