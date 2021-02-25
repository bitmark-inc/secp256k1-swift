import XCTest

import secp256k1_swiftTests

var tests = [XCTestCaseEntry]()
tests += secp256k1_swiftTests.allTests()
XCTMain(tests)
