// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Secp256k1",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "Secp256k1",
            targets: ["secp256k1_swift"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.]
        .target(
            name: "secp256k1_c",
            path: "Sources/secp256k1-c",
            exclude: [
                "secp256k1/src/asm",
                "secp256k1/src/bench_ecdh.c",
                "secp256k1/src/bench_ecmult.c",
                "secp256k1/src/bench_internal.c",
                "secp256k1/src/bench_recover.c",
                "secp256k1/src/bench_schnorrsig.c",
                "secp256k1/src/bench_sign.c",
                "secp256k1/src/bench_verify.c",
                "secp256k1/src/gen_context.c",
                "secp256k1/src/modules/extrakeys/tests_impl.h",
                "secp256k1/src/modules/schnorrsig/tests_impl.h",
                "secp256k1/src/tests_exhaustive.c",
                "secp256k1/src/tests.c",
                "secp256k1/src/valgrind_ctime_test.c"
            ],
            cSettings: [
                .headerSearchPath("secp256k1"),
                // Basic config values that are universal and require no dependencies.
                // https://github.com/bitcoin-core/secp256k1/blob/master/src/basic-config.h#L27-L31
                .define("ECMULT_WINDOW_SIZE", to: "15", nil),
                .define("ECMULT_GEN_PREC_BITS", to: "4", nil),
                .define("SECP256K1_ECDH_H"),
                .define("SECP256K1_MODULE_ECDH_MAIN_H"),
                .define("SECP256K1_EXTRAKEYS_H"),
                .define("SECP256K1_MODULE_EXTRAKEYS_MAIN_H"),
                .define("SECP256K1_SCHNORRSIG_H"),
                .define("SECP256K1_MODULE_SCHNORRSIG_MAIN_H"),
                .define("USE_NUM_NONE"),
                .define("USE_FIELD_INV_BUILTIN"),
                .define("USE_SCALAR_INV_BUILTIN"),
                .define("USE_WIDEMUL_64")
            ]
        ),
        .target(
            name: "secp256k1_swift",
            dependencies: [
                .target(name: "secp256k1_c")
            ],
            path: "Sources/secp256k1-swift",
            sources: [
                "swift-crypto/Sources/Crypto/Util/SecureBytes.swift",
                "swift-crypto/Sources/Crypto/Util/BoringSSL/RNG_boring.swift",
                "swift-crypto/Sources/Crypto/Util/BoringSSL/SafeCompare_boring.swift",
                "SafeCompare.swift",
                "Secp256k1.swift",
                "Secp256k1Error.swift",
                "Utilities.swift"
            ]
        ),
        .testTarget(
            name: "secp256k1-swiftTests",
            dependencies: ["secp256k1_c", "secp256k1_swift"]),
    ]
)
