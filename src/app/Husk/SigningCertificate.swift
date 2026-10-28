// SPDX-License-Identifier: GPL-2.0-or-later
import CryptoKit
import Foundation
import Security
import UIKit

/// The developer certificate JIT-less mode signs a game's converted libraries with (JITLess.swift). iOS loads a library in a
/// sideloaded app only when it is signed by the same team as the app, so this has to be the certificate SideStore or AltStore
/// installed Husk with. It comes from the store itself (it hands it over through a URL callback) or from a .p12 file and its
/// password. Kept in the Keychain; nothing leaves the device.
@MainActor
final class SigningCertificate: ObservableObject {
    static let shared = SigningCertificate()

    struct Info: Equatable {
        let teamID: String
        let expires: Date
        /// Names this certificate in the converted libraries' .signer files: a new one means they are signed again.
        let tag: String
    }

    @Published private(set) var info: Info?
    @Published var lastError: String?

    private static let service = "com.husk.signing"
    private static let callbackScheme = "husk"
    private static let callbackHost = "certificate"

    private init() { info = Self.loadStored().flatMap { Self.inspect($0.p12, $0.password) } }

    // MARK: - what the signer needs

    /// The certificate and password, for signing (read from the Keychain each time).
    nonisolated static func credentials() -> (p12: Data, password: String, tag: String)? {
        guard let s = loadStored() else { return nil }
        return (s.p12, s.password, tag(s.p12))
    }

    // MARK: - importing

    /// A .p12 file and its password (empty when it has none).
    func importP12(_ data: Data, password: String) {
        guard let found = Self.inspect(data, password) else {
            lastError = "That certificate could not be opened. Check the password."
            return
        }
        if let team = Self.installedTeamID, team != found.teamID {
            lastError = "This certificate belongs to team \(found.teamID), but Husk was installed with team \(team). "
                      + "Use the certificate of the Apple ID that installed Husk."
            return
        }
        guard Self.store(data, password) else { lastError = "The certificate could not be saved in the Keychain."; return }
        info = found
        lastError = nil
        HuskLog.log("sign", "certificate imported: team \(found.teamID), expires \(found.expires)")
    }

    /// Ask SideStore or AltStore for the certificate it signs Husk with; it answers by opening husk://certificate?cert=…&password=…
    func requestFromStore(_ store: Store) {
        let callback = "\(Self.callbackScheme)://\(Self.callbackHost)?cert=$(BASE64_CERT)&password=$(PASSWORD)"
        guard let encoded = callback.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
              let url = URL(string: "\(store.scheme)://certificate?callback_template=\(encoded)") else { return }
        HuskLog.log("sign", "asking \(store.title) for its certificate")
        UIApplication.shared.open(url) { [weak self] ok in
            if !ok { Task { @MainActor in self?.lastError = "\(store.title) is not installed, or did not answer." } }
        }
    }

    /// husk://certificate?cert=<base64>&password=<password>, from SideStore or AltStore. False when the URL is not one.
    func handle(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == Self.callbackScheme, url.host?.lowercased() == Self.callbackHost else { return false }
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ name: String) -> String? { items.first { $0.name.lowercased() == name }?.value }
        // a base64 '+' may arrive as a space
        guard let cert = value("cert")?.replacingOccurrences(of: " ", with: "+"), let data = Data(base64Encoded: cert) else {
            lastError = "The store's answer had no certificate in it."
            return true
        }
        importP12(data, password: value("password") ?? "")
        return true
    }

    func remove() {
        for account in ["p12", "password"] {
            SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: Self.service, kSecAttrAccount: account] as CFDictionary)
        }
        info = nil
        HuskLog.log("sign", "certificate removed")
    }

    enum Store: CaseIterable, Identifiable {
        case sideStore, altStore
        var id: Self { self }
        var title: String { self == .sideStore ? "SideStore" : "AltStore" }
        var scheme: String { self == .sideStore ? "sidestore" : "altstore-classic" }
    }

    // MARK: - the team Husk was installed with

    /// From the provisioning profile the sideloader embedded; nil when there is none (TrollStore, a development build).
    nonisolated static var installedTeamID: String? {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let raw = try? Data(contentsOf: url),
              let start = raw.range(of: Data("<?xml".utf8)), let end = raw.range(of: Data("</plist>".utf8), in: start.lowerBound..<raw.endIndex),
              let plist = try? PropertyListSerialization.propertyList(from: raw[start.lowerBound..<end.upperBound], format: nil) as? [String: Any]
        else { return nil }
        return (plist["TeamIdentifier"] as? [String])?.first
    }

    // MARK: - Keychain and inspection

    private nonisolated static func inspect(_ p12: Data, _ password: String) -> Info? {
        var team = [CChar](repeating: 0, count: 64), err = [CChar](repeating: 0, count: 200)
        var notAfter: Double = 0
        let ok = p12.withUnsafeBytes { b in
            husk_p12_info(b.bindMemory(to: UInt8.self).baseAddress, b.count, password, &team, team.count, &notAfter, &err, err.count)
        }
        guard ok else { HuskLog.log("sign", "certificate not usable: \(String(cString: err))"); return nil }
        return Info(teamID: String(cString: team), expires: Date(timeIntervalSince1970: notAfter), tag: tag(p12))
    }

    private nonisolated static func tag(_ p12: Data) -> String {
        SHA256.hash(data: p12).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    private nonisolated static func store(_ p12: Data, _ password: String) -> Bool {
        func put(_ account: String, _ value: Data) -> Bool {
            let key: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
            SecItemDelete(key as CFDictionary)
            var add = key
            add[kSecValueData] = value
            add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
        }
        return put("p12", p12) && put("password", Data(password.utf8))
    }

    private nonisolated static func loadStored() -> (p12: Data, password: String)? {
        func get(_ account: String) -> Data? {
            var out: CFTypeRef?
            let q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account,
                                      kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne]
            return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
        }
        guard let p12 = get("p12") else { return nil }
        return (p12, get("password").flatMap { String(data: $0, encoding: .utf8) } ?? "")
    }
}
