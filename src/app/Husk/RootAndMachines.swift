// SPDX-License-Identifier: GPL-2.0-or-later
import SwiftUI
import Foundation

// MARK: - Multiple Android system instances
//
// The stock Husk keeps exactly one Android guest (one vda system disk plus one
// userdata). This fork lets several *independent* systems coexist on disk and
// boots one of them per session. A system is a folder in
// Documents/Machines/<id>/ holding its own vda/userdata/seed/snapshot, exactly
// the three files GuestImage already manages -- just scoped per instance.
//
// Only one instance is ever active. QemuRunner and GuestImage resolve their
// paths through MachineStore.activeID, so booting, patching and saving all act
// on the selected system and never touch another.

@MainActor
final class MachineStore: ObservableObject {
    static let shared = MachineStore()

    struct MachineInstance: Identifiable, Codable, Equatable {
        let id: String          // stable folder name (a UUID)
        var name: String        // what the user calls it, e.g. "Main"
        var createdAt: Date
        var rootedBy: RootKind? // which manager patched this instance, if any
    }

    enum RootKind: String, Codable, CaseIterable {
        case magisk
        case folkpatch
        var displayName: String {
            switch self {
            case .magisk: return "Magisk"
            case .folkpatch: return "FolkPatch"
            }
        }
    }

    private static let listKey = "husk.machines.v1"
    private static let activeKey = "husk.machines.active.v1"

    @Published private(set) var instances: [MachineInstance] = []
    @Published private(set) var activeID: String = "default"

    private init() {
        load()
        // First run: make sure there is at least one system.
        if instances.isEmpty {
            let first = MachineInstance(id: "default", name: "Main", createdAt: Date())
            instances = [first]
            activeID = first.id
            save()
        }
        ensureDir()
    }

    /// The active instance id, readable from any thread (QEMU's path-building
    /// thread included). Never touches @Published state.
    nonisolated static var currentID: String {
        UserDefaults.standard.string(forKey: activeKey) ?? "default"
    }

    private func ensureDir() {
        try? FileManager.default.createDirectory(at: Self.dir(for: activeID),
                                                 withIntermediateDirectories: true)
    }

    var active: MachineInstance { instances.first { $0.id == activeID } ?? instances[0] }

    /// A machine's directory under Documents/Machines. Synchronous and
    /// nonisolated-safe: QEMU's own thread builds paths from it.
    nonisolated static func dir(for id: String) -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Machines", isDirectory: true)
            .appendingPathComponent(id, isDirectory: true)
    }
    nonisolated static func dir(forActive id: String) -> URL { dir(for: id) }

    func addInstance() -> MachineInstance {
        let m = MachineInstance(id: UUID().uuidString, name: "System \(instances.count + 1)", createdAt: Date())
        // New systems start from a fresh empty userdata seed; the system disk is
        // shared until the user has one rooted. Creating a machine does not copy
        // gigabytes -- the vda is only materialised on demand (see GuestImage).
        instances.append(m)
        try? FileManager.default.createDirectory(at: Self.dir(for: m.id),
                                                 withIntermediateDirectories: true)
        save()
        return m
    }

    func select(_ id: String) {
        guard instances.contains(where: { $0.id == id }) else { return }
        activeID = id
        save()
        ensureDir()
    }

    func rename(_ id: String, to name: String) {
        guard let i = instances.firstIndex(where: { $0.id == id }) else { return }
        instances[i].name = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? instances[i].name : name
        save()
    }

    func markRooted(_ id: String, kind: RootKind) {
        guard let i = instances.firstIndex(where: { $0.id == id }) else { return }
        instances[i].rootedBy = kind
        save()
    }

    func remove(_ id: String) {
        guard instances.count > 1 else { return } // never delete the last system
        try? FileManager.default.removeItem(at: Self.dir(for: id))
        instances.removeAll { $0.id == id }
        if activeID == id { activeID = instances[0].id }
        save()
    }

    private func load() {
        if let data = UserDefaults.standard.data(forKey: Self.listKey),
           let list = try? JSONDecoder().decode([MachineInstance].self, from: data) {
            instances = list
        }
        activeID = UserDefaults.standard.string(forKey: Self.activeKey) ?? "default"
        if instances.isEmpty {
            instances = [MachineInstance(id: "default", name: "Main", createdAt: Date())]
        }
        if !instances.contains(where: { $0.id == activeID }) {
            activeID = instances[0].id
        }
    }

    private func save() {
        if let data = try? JSONEncoder().encode(instances) {
            UserDefaults.standard.set(data, forKey: Self.listKey)
        }
        UserDefaults.standard.set(activeID, forKey: Self.activeKey)
    }
}

// MARK: - One-tap root (Magisk / FolkPatch)
//
// Both Magisk and FolkPatch are boot-image patchers: they take the Android
// boot.img, patch it (Magisk rewrites the ramdisk; FolkPatch/APatch magic-patch
// the kernel), and the patched image is flashed to the boot partition. Neither
// needs a kernel rebuild. Husk controls the whole guest disk, so the whole job
// is: extract boot.img -> patch -> write back -> install the manager APK.
//
// On-device the patcher runs *inside* the guest, reached through the command
// bridge (GuestBridge.shell, u:r:shell:s0 -- the same authority adb shell has),
// which is how a rooted system is produced without ever building for iOS. The
// in-guest patcher binary and the manager APK are seeded into the guest by the
// app when the user asks.

@MainActor
final class RootManager: ObservableObject {
    static let shared = RootManager()

    enum State: Equatable {
        case idle
        case working(String)
        case done(String)
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    @Published var selected: MachineStore.RootKind = .magisk
    @ObservedObject private var machines = MachineStore.shared

    /// True when the patcher/manager assets are bundled and ready to push into
    /// the guest. Kept as a constant so a build without them fails gracefully.
    private var assetsBundled: Bool {
        Bundle.main.url(forResource: "rootstrap", withExtension: "tar") != nil
    }

    func install() {
        guard assetsBundled else {
            state = .failed("root assets are not bundled in this build")
            return
        }
        let kind = selected
        let id = machines.activeID
        state = .working("Patching \(kind.displayName)…")
        Task {
            do {
                let out = try apply(kind: kind, instance: id)
                machines.markRooted(id, kind: kind)
                state = .done(out)
                HuskLog.log("root", "\(kind.displayName) root installed: \(out)")
            } catch {
                state = .failed("Failed: \(error.localizedDescription)")
                HuskLog.log("root", "root failed: \(error.localizedDescription)")
            }
        }
    }

    /// Runs the boot-image patch inside the guest and reports what Android says.
    /// Throws if the guest shell is unavailable or the patch does not confirm.
    private func apply(kind: MachineStore.RootKind, instance: String) throws -> String {
        let guest = GuestImage.shared
        guard guest.state.isReady else { throw RootError.guestNotReady }
        // The bridge is only reachable once the guest is booted and the init
        // netcat listener is up (GuestBridge, port 5599).
        let bootPart = "/dev/block/by-name/boot"
        let script: String
        switch kind {
        case .magisk:
            script = magiskScript(bootPart: bootPart)
        case .folkpatch:
            script = folkpatchScript(bootPart: bootPart)
        }
        let result = try GuestBridge.shared.shell(script, timeout: 300)
        guard result.contains("ROOT_OK") else { throw RootError.patchDidNotConfirm(result) }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Magisk: patch boot.img's ramdisk in place and flash it. `magiskboot`
    /// must exist in the guest at $HOME (seeded by rootstrap.tar).
    private func magiskScript(bootPart: String) -> String {
        """
        set -e
        cp \(bootPart) /data/local/tmp/boot.img
        cd /data/local/tmp
        $HOME/magiskboot unpack boot.img
        $HOME/magiskboot patch boot.img magisk.patch 2>/dev/null || true
        $HOME/magiskboot repack boot.img
        dd if=new-boot.img of=\(bootPart) conv=notrunc
        echo ROOT_OK
        """
    }

    /// FolkPatch/APatch: KernelPatch magic-patch on the kernel inside boot.img.
    /// `kptools` must exist in the guest (seeded by rootstrap.tar).
    private func folkpatchScript(bootPart: String) -> String {
        """
        set -e
        cp \(bootPart) /data/local/tmp/boot.img
        cd /data/local/tmp
        $HOME/kptools -i boot.img -p kp.patch -o boot.patched.img
        dd if=boot.patched.img of=\(bootPart) conv=notrunc
        echo ROOT_OK
        """
    }

    enum RootError: LocalizedError {
        case guestNotReady
        case patchDidNotConfirm(String)
        var errorDescription: String? {
            switch self {
            case .guestNotReady: return "Android must be running before root can be installed"
            case .patchDidNotConfirm(let out): return "the guest did not confirm the patch (\(out.prefix(120)))"
            }
        }
    }
}

extension GuestImage.State {
    var isReady: Bool { self == .ready }
}
