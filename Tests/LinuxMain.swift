import XCTest

import Secp256k1SwiftTests

var tests = [XCTestCaseEntry]()
tests += Secp256k1SwiftTests.allTests()
XCTMain(tests)
