import Foundation
import Darwin
@testable import AppSweepCore

/// These samples catch a discovery implementation that silently leaves the new
/// categories read-only, or classifies attachment/model copies as default junk.
@MainActor func additionalCategoryDiscoveryChecks() async throws {
    let f = try OwnedFixture()
    let trash = f.home + "/.Trash/discarded-note.txt"
    let mail = f.home + "/Library/Mail Downloads/52E32806-7C8E-42FA-9AC5-E55AB61EE797"
    let model = f.home + "/.cache/huggingface/hub/models--owned--fixture"
    for path in [f.home + "/.Trash", mail, model + "/blobs", model + "/refs", model + "/snapshots/" + String(repeating: "a", count: 40)] {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    try Data("Already discarded by the fixture owner".utf8).write(to: URL(fileURLWithPath: trash))
    try Data("Attachment copy may contain user edits".utf8).write(to: URL(fileURLWithPath: mail + "/edited-note.txt"))
    try Data(String(repeating: "a", count: 40).utf8).write(to: URL(fileURLWithPath: model + "/refs/main"))
    let tensorHeader = Data("{\"weight\":{\"dtype\":\"F32\",\"shape\":[1],\"data_offsets\":[0,4]}}".utf8)
    var length = UInt64(tensorHeader.count).littleEndian
    var tensor = withUnsafeBytes(of: &length) { Data($0) }
    tensor.append(tensorHeader); tensor.append(Data([0,0,0,0]))
    try tensor.write(to: URL(fileURLWithPath: model + "/blobs/" + String(repeating: "b", count: 64)))
    try fm.createSymbolicLink(atPath: model + "/snapshots/" + String(repeating: "a", count: 40) + "/model.safetensors", withDestinationPath: "../../blobs/" + String(repeating: "b", count: 64))
    try additionalCategoryRuleGuards(f: f, trash: trash, mail: mail, model: model, tensor: tensor)
    let rules: Set<String> = ["current-user-trash-entry-v1", "mail-download-copy-v1", "ai-huggingface-local-repository-v1"]
    let engine = try f.engine(rules: rules)
    let report = try await engine.scanJunk()
    let items = report.selectableCandidates(includeUserData: true).filter { rules.contains($0.rule) }
    try check(Set(items.map(\.path)) == [trash, mail, model], "Trash, Mail download copy and whole independent model repository must be actionable after explicit selection: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
    try check(items.allSatisfy { !$0.selectedByDefault && $0.category == .userData }, "Trash, mail copies and local models must never be selected as default junk")
    print("PASS new categories have actionable discovery; mail/model data requires explicit selection")
    do {
        _ = try await engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: false)
        throw CheckFailure("New personal-data categories bypassed explicit opt-in")
    } catch let error as CheckFailure { throw error } catch { }
    let originals = try items.map { try SafeFilesystem.snapshot($0.path, allowInternalLinks: $0.path == model, purpose: .managedData) }
    let plan = try await engine.makePlan(reportID: report.id, selected: Set(items.map(\.id)), includeUserData: true)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Additional categories isolation failed: " + (batch.issue ?? "") + batch.entries.compactMap(\.message).joined(separator: "; "))
    for item in items { try check(!fm.fileExists(atPath: item.path), "Selected personal-data entry was not isolated") }
    let restored = try await f.engine(rules: rules).restore(batchID: batch.id)
    try check(restored.status == .restored, "Additional categories fresh-engine recovery failed: " + (restored.issue ?? "") + restored.entries.compactMap(\.message).joined(separator: "; "))
    for (index, item) in items.enumerated() {
        let after = try SafeFilesystem.snapshot(item.path, allowInternalLinks: item.path == model, purpose: .managedData)
        try check(after.identity.sameObject(as: originals[index].identity) && after.tree == originals[index].tree, "Recovered personal data changed identity or contents")
    }
    try check(Data(contentsOf: URL(fileURLWithPath: model + "/blobs/" + String(repeating: "b", count: 64))) == tensor, "Recovered model weights changed")
    print("PASS explicit opt-in, whole-object isolation and fresh-engine byte/identity recovery")

    let conflictEngine = try f.engine(rules: rules), conflictReport = try await conflictEngine.scanJunk()
    guard let trashItem = conflictReport.selectableCandidates(includeUserData: true).first(where: { $0.path == trash }) else { throw CheckFailure("Trash fixture missing after restore") }
    let conflictPlan = try await conflictEngine.makePlan(reportID: conflictReport.id, selected: [trashItem.id], includeUserData: true)
    let conflictBatch = try await conflictEngine.execute(planID: conflictPlan.id)
    try check(conflictBatch.status == .isolated, "Trash conflict sample did not isolate")
    let trashParent = f.home + "/.Trash", originalMode = try SafeDirectory(path: trashParent).ownIdentity.mode
    let writeGrant = "everyone allow write,append,delete_child"
    _ = try BoundedProcess.run("/bin/chmod", arguments: ["+a", writeGrant, trashParent], timeout: 3)
    try check(SafeDirectory(path: trashParent).ownIdentity.mode == originalMode, "ACL sample unexpectedly changed POSIX mode")
    let unsafeDestination = try await f.engine(rules: rules).restore(batchID: conflictBatch.id)
    try check(unsafeDestination.status != .restored && !fm.fileExists(atPath: trash), "Recovery restored into a newly shared destination")
    _ = try BoundedProcess.run("/bin/chmod", arguments: ["-a", writeGrant, trashParent], timeout: 3)
    try check(SafeDirectory(path: trashParent).ownIdentity.mode == originalMode, "Removing only the test ACL changed POSIX mode")
    try Data("New independent Trash occupant".utf8).write(to: URL(fileURLWithPath: trash))
    let conflict = try await f.engine(rules: rules).restore(batchID: conflictBatch.id)
    try check(conflict.status != .restored && String(contentsOfFile: trash, encoding: .utf8) == "New independent Trash occupant", "Recovery overwrote a new Trash entry")
    try fm.moveItem(atPath: trash, toPath: f.home + "/new-trash-occupant-held")
    let resolved = try await f.engine(rules: rules).restore(batchID: conflictBatch.id)
    try check(resolved.status == .restored && String(contentsOfFile: trash, encoding: .utf8) == "Already discarded by the fixture owner", "Conflict-safe Trash recovery failed")
    print("PASS an existing destination survives recovery conflict and original restores after conflict is moved")

    let staleEngine = try f.engine(rules: rules), staleReport = try await staleEngine.scanJunk()
    guard let mailItem = staleReport.selectableCandidates(includeUserData: true).first(where: { $0.path == mail }) else { throw CheckFailure("Mail fixture missing after restore") }
    let stalePlan = try await staleEngine.makePlan(reportID: staleReport.id, selected: [mailItem.id], includeUserData: true)
    try Data("Later attachment edit must be preserved".utf8).write(to: URL(fileURLWithPath: mail + "/edited-note.txt"))
    do { _ = try await staleEngine.execute(planID: stalePlan.id); throw CheckFailure("Changed Mail copy moved under an old plan") }
    catch let error as CheckFailure { throw error } catch { }
    try check(String(contentsOfFile: mail + "/edited-note.txt", encoding: .utf8) == "Later attachment edit must be preserved", "Stale Mail plan changed the newer edit")

    let busyEngine = try f.engine(rules: rules), busyReport = try await busyEngine.scanJunk()
    guard let modelItem = busyReport.selectableCandidates(includeUserData: true).first(where: { $0.path == model }) else { throw CheckFailure("Model fixture missing after restore") }
    let busyPlan = try await busyEngine.makePlan(reportID: busyReport.id, selected: [modelItem.id], includeUserData: true)
    let held = open(model + "/blobs/" + String(repeating: "b", count: 64), O_RDONLY | O_CLOEXEC)
    try check(held >= 0, "Cannot open owned model occupancy sample")
    do { _ = try await busyEngine.execute(planID: busyPlan.id); _ = close(held); throw CheckFailure("Actively opened model weights moved") }
    catch let error as CheckFailure { throw error } catch { _ = close(held) }
    try check(fm.fileExists(atPath: model), "Busy model repository was moved")
    print("PASS changed Mail data invalidates reviewed plan; real open model weights veto execution")
    try await additionalMailDestinationChecks(f: f, rules: rules)
    try f.finish()
}

@MainActor private func additionalMailDestinationChecks(f: OwnedFixture, rules: Set<String>) async throws {
    let container = f.home + "/Library/Containers/com.apple.mail"
    let metadata = container + "/.com.apple.containermanagerd.metadata.plist"
    let metadataBytes = try Data(contentsOf: URL(fileURLWithPath: metadata))
    let modern = container + "/Data/Library/Mail Downloads/16E32806-7C8E-42FA-9AC5-E55AB61EE797"
    try fm.createDirectory(atPath: modern, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    try Data("Container download copy".utf8).write(to: URL(fileURLWithPath: modern + "/copy.txt"))
    let engine = try f.engine(rules: rules), report = try await engine.scanJunk()
    guard let item = report.selectableCandidates(includeUserData: true).first(where: { $0.path == modern }) else { throw CheckFailure("Valid native-style Mail download copy was not actionable") }
    let plan = try await engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: true)
    let batch = try await engine.execute(planID: plan.id)
    try check(batch.status == .isolated, "Container Mail copy did not isolate")
    let changed: [String: Any] = ["MCMMetadataIdentifier":"org.example.other-mail", "MCMMetadataContentClass":2, "MCMMetadataUserIdentity":["posixUID":getuid()]]
    try PropertyListSerialization.data(fromPropertyList: changed, format: .binary, options: 0).write(to: URL(fileURLWithPath: metadata))
    let retained = try await f.engine(rules: rules).restore(batchID: batch.id)
    try check(retained.status != .restored && !fm.fileExists(atPath: modern), "Recovery ignored changed Mail container identity")
    try metadataBytes.write(to: URL(fileURLWithPath: metadata))
    let restored = try await f.engine(rules: rules).restore(batchID: batch.id)
    try check(restored.status == .restored && String(contentsOfFile: modern + "/copy.txt", encoding: .utf8) == "Container download copy", "Mail copy did not recover after destination identity restored")
    print("PASS native-style Mail container copy isolation and destination identity revalidation on recovery")
}

/// Removing any ownership/topology/format check below permits a concrete unsafe
/// fixture; no private user data or live installed application is modified.
@MainActor private func additionalCategoryRuleGuards(f: OwnedFixture, trash: String, mail: String, model: String, tensor: Data) throws {
    let outside = f.home + "/outside-sentinel"
    try Data("External object must survive".utf8).write(to: URL(fileURLWithPath: outside))
    let outsideIdentity = try SafeDirectory(path: f.home).identity("outside-sentinel")
    let outsideBytes = try Data(contentsOf: URL(fileURLWithPath: outside))
    for path in [f.home + "/.Trash", trash + "/child", f.home + "/.Trash/../outside-sentinel", f.home + "/Downloads/discarded-note.txt", f.home + "/.Trash/.DS_Store"] {
        try check(!TrashEntryRule.matches(path: path, home: f.home), "Trash rule widened outside direct reviewed entries")
    }
    try fm.createSymbolicLink(atPath: f.home + "/.Trash/alias", withDestinationPath: outside)
    try reject("Trash alias is retained without following its target") { _ = try TrashEntryRule.verify(path: f.home + "/.Trash/alias", home: f.home) }
    try fm.removeItem(atPath: f.home + "/.Trash/alias")
    try fm.linkItem(atPath: trash, toPath: f.home + "/trash-hardlink")
    try reject("Trash with an external hard link is retained") { _ = try TrashEntryRule.verify(path: trash, home: f.home) }
    try fm.removeItem(atPath: f.home + "/trash-hardlink")
    try check(chmod(f.home + "/.Trash", 0o777) == 0, "Cannot prepare shared fixture ancestor")
    try reject("Shared Trash ancestor is retained") { _ = try TrashEntryRule.verify(path: trash, home: f.home) }
    try check(chmod(f.home + "/.Trash", 0o700) == 0, "Cannot restore fixture permissions")
    for path in [f.home + "/Library/Mail/V10/52E32806-7C8E-42FA-9AC5-E55AB61EE797", f.home + "/Downloads/52E32806-7C8E-42FA-9AC5-E55AB61EE797", mail + "/edited-note.txt", f.home + "/Library/Mail Downloads/personal-folder"] {
        try check(!MailDownloadRule.matches(path: path, home: f.home), "Mail rule accepted live storage or an unknown download group")
    }
    try fm.createSymbolicLink(atPath: mail + "/alias", withDestinationPath: outside)
    try reject("Mail download group with an outside link stays retained") { _ = try MailDownloadRule.verify(path: mail, home: f.home) }
    try fm.removeItem(atPath: mail + "/alias")
    let container = f.home + "/Library/Containers/com.apple.mail"
    let modern = container + "/Data/Library/Mail Downloads/16E32806-7C8E-42FA-9AC5-E55AB61EE797"
    try fm.createDirectory(atPath: modern, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try Data("Downloaded copy".utf8).write(to: URL(fileURLWithPath: modern + "/copy.txt"))
    try reject("Named Mail container without identity evidence is retained") { _ = try MailDownloadRule.verify(path: modern, home: f.home) }
    let info: [String: Any] = ["MCMMetadataIdentifier":"com.apple.mail", "MCMMetadataContentClass":2, "MCMMetadataUserIdentity":["posixUID":getuid()]]
    let metadata = container + "/.com.apple.containermanagerd.metadata.plist"
    try PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0).write(to: URL(fileURLWithPath: metadata))
    _ = try MailDownloadRule.verify(path: modern, home: f.home)
    var wrongOwner = info; wrongOwner["MCMMetadataOwnership"] = ["uid": getuid() + 1]
    try PropertyListSerialization.data(fromPropertyList: wrongOwner, format: .binary, options: 0).write(to: URL(fileURLWithPath: metadata))
    try reject("Present but conflicting Mail ownership stays retained") { _ = try MailDownloadRule.verify(path: modern, home: f.home) }
    try fm.removeItem(atPath: modern)
    try reject("Mail destination metadata must still be valid when copy is isolated") { try MailDownloadRule.verifyDestination(path: modern, home: f.home) }
    try PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0).write(to: URL(fileURLWithPath: metadata))
    try MailDownloadRule.verifyDestination(path: modern, home: f.home)
    let mailDestination = URL(fileURLWithPath: modern).deletingLastPathComponent().path
    try check(chmod(mailDestination, 0o777) == 0, "Cannot prepare changed Mail destination permissions")
    try reject("Mail restore destination with shared write access is retained") { try MailDownloadRule.verifyDestination(path: modern, home: f.home) }
    try check(chmod(mailDestination, 0o700) == 0, "Cannot restore Mail destination fixture permissions")
    try MailDownloadRule.verifyDestination(path: modern, home: f.home)
    print("PASS Mail live-store exclusion and container identity; optional supplemental ownership is respected")

    let blob = model + "/blobs/" + String(repeating: "b", count: 64)
    let link = model + "/snapshots/" + String(repeating: "a", count: 40) + "/model.safetensors"
    for path in [model + "/blobs/" + String(repeating: "b", count: 64), model + "/snapshots/" + String(repeating: "a", count: 40), f.home + "/.cache/huggingface/hub/datasets--owned--fixture", f.home + "/.ollama/models"] {
        try check(!AIStorageRule.matches(path: path, home: f.home), "AI rule widened to an individual reference/shared/unknown store")
    }
    try fm.removeItem(atPath: blob)
    try fm.createSymbolicLink(atPath: blob, withDestinationPath: outside)
    try reject("Cross-repository shared HF blob is retained") { _ = try AIStorageRule.verify(path: model, home: f.home) }
    try fm.removeItem(atPath: blob); try tensor.write(to: URL(fileURLWithPath: blob))
    try fm.removeItem(atPath: link); try fm.createSymbolicLink(atPath: link, withDestinationPath: outside)
    try reject("HF snapshot cannot follow an external model link") { _ = try AIStorageRule.verify(path: model, home: f.home) }
    try fm.removeItem(atPath: link); try fm.createSymbolicLink(atPath: link, withDestinationPath: "../../blobs/missing/../" + String(repeating: "b", count: 64))
    try reject("HF target normalization cannot hide an unverified path component") { _ = try AIStorageRule.verify(path: model, home: f.home) }
    try fm.removeItem(atPath: link); try fm.createSymbolicLink(atPath: link, withDestinationPath: "../../blobs/" + String(repeating: "b", count: 64))
    for path in [model + "/unexpected-notes.txt", model + "/blobs/" + String(repeating: "c", count: 64), model + "/blobs/" + String(repeating: "b", count: 64) + ".incomplete"] {
        try Data("Unknown data".utf8).write(to: URL(fileURLWithPath: path))
        try reject("HF unknown, unreferenced or incomplete content remains retained") { _ = try AIStorageRule.verify(path: model, home: f.home) }
        try fm.removeItem(atPath: path)
    }
    try Data(String(repeating: "c", count: 40).utf8).write(to: URL(fileURLWithPath: model + "/refs/main"))
    try reject("HF branch cannot reference a missing snapshot") { _ = try AIStorageRule.verify(path: model, home: f.home) }
    try Data(String(repeating: "a", count: 40).utf8).write(to: URL(fileURLWithPath: model + "/refs/main"))
    try Data("not a completed tensor payload".utf8).write(to: URL(fileURLWithPath: blob))
    try reject("Model filename alone does not establish Safetensors format") { _ = try AIStorageRule.verify(path: model, home: f.home) }
    try tensor.write(to: URL(fileURLWithPath: blob)); _ = try AIStorageRule.verify(path: model, home: f.home)
    try check(!AIStorageRule.isConsumer("/usr/bin/python3 unrelated-service.py") && !AIStorageRule.isConsumer("/usr/local/bin/node unrelated-server.js") && !AIStorageRule.isConsumer("/usr/bin/java -jar ordinary.jar"), "Unrelated generic runtime globally blocks models")
    try check(AIStorageRule.isConsumer("/usr/local/bin/hf download owned/model") && AIStorageRule.isConsumer("/usr/bin/python3 -m mlx_lm.generate"), "Explicit model producer was missed")
    let producerPath = f.home + "/hf"
    try fm.copyItem(atPath: "/bin/sleep", toPath: producerPath)
    let producer = Process(); producer.executableURL = URL(fileURLWithPath: producerPath); producer.arguments = ["30"]
    try producer.run()
    defer { if producer.isRunning { producer.terminate() }; producer.waitUntilExit() }
    try reject("Actual named model producer process blocks the repository") { try AIStorageRule.ensureStopped(path: model, home: f.home) }
    try assertExternal(outside, identity: outsideIdentity, bytes: outsideBytes)
    print("PASS model topology, model format and explicit activity boundaries; outside object unchanged")
}
