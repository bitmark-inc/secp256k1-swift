import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(secp256k1_swiftTests.allTests),
    ]
}
#endif
