#if os(macOS)
import Foundation
import Security
import CFSafety
import Darwin

enum PreferenceDomainReader {
    // The standard installation directory permits administrators to install
    // applications. This exception never applies inside the signed bundle or
    // to a cache/data directory, and grants no write authority.
    static func trustedInstallationDirectory(path: String, fd: Int32) -> Bool {
        guard path == "/Applications" else { return false }
        var metadata=stat(), current=stat()
        guard fstat(fd,&metadata) == 0, lstat(path,&current) == 0,
              metadata.st_dev == current.st_dev, metadata.st_ino == current.st_ino,
              metadata.st_uid == 0, metadata.st_gid == 80,
              metadata.st_mode & 0o170000 == 0o040000,
              metadata.st_mode & 0o7777 == 0o775,
              as_no_grant_acl_descriptor(fd) == 1 else { return false }
        return true
    }
    static func read(home: String, identifier: String, timeout: TimeInterval) throws -> Data {
        let program=try executable()
        try SafeFilesystem.verify(program)
        let result=try BoundedProcess.capture("/usr/bin/env",arguments:["-i","HOME=" + home,"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",program.path,"_native-preference-export",identifier],timeout:timeout,mergeStderr:false)
        guard result.status == 0, let bytes=Data(base64Encoded:result.text.trimmingCharacters(in:.whitespacesAndNewlines)), !bytes.isEmpty else { throw SweepError.incomplete("原生偏好读取进程失败，服务状态未确认") }
        try SafeFilesystem.verify(program)
        return bytes
    }
    private static func executable() throws -> FileSnapshot {
        let bundle=Bundle.main
        let path: String
        if bundle.bundleIdentifier == "org.appsweep.app", bundle.bundleURL.pathExtension == "app" {
            guard AppInspector.signatureMatches(path:bundle.bundleURL.path,identifier:"org.appsweep.app") else { throw SweepError.denied("App Sweep 包签名未确认，不能运行内部读取进程") }
            path=bundle.bundleURL.appendingPathComponent("Contents/MacOS/app-sweep").path
        } else if let own=bundle.executableURL, own.lastPathComponent == "app-sweep" {
            path=own.path
        } else {
            #if DEBUG
            // SwiftPM native tests use the already built CLI beside their test
            // bundle. No environment variable or decoded path selects code.
            guard let testBundle=Bundle.allBundles.first(where:{ $0.bundleURL.lastPathComponent == "AppSweepPackageTests.xctest" }) else { throw SweepError.incomplete("未找到同一构建的偏好读取程序") }
            path=testBundle.bundleURL.deletingLastPathComponent().appendingPathComponent("app-sweep").path
            #else
            throw SweepError.incomplete("偏好读取入口不属于 App Sweep 应用包或命令行")
            #endif
        }
        let snapshot=try SafeFilesystem.snapshot(path)
        guard snapshot.identity.mode & 0o170000 == 0o100000, snapshot.identity.mode & 0o111 != 0,
              snapshot.identity.mode & 0o022 == 0, snapshot.identity.links == 1,
              snapshot.identity.size > 0, snapshot.identity.size <= 128*1024*1024 else { throw SweepError.denied("内部偏好读取程序的文件身份不安全") }
        for ancestor in snapshot.ancestors {
            let directory=try SafeDirectory(path:ancestor.path)
            guard as_unshared_node_descriptor(directory.fd,ancestor.owner) == 1 || trustedInstallationDirectory(path:ancestor.path,fd:directory.fd) else { throw SweepError.denied("内部读取程序的祖先目录可被其他用户改写") }
        }
        let url=URL(fileURLWithPath:path),parent=try SafeDirectory(path:url.deletingLastPathComponent().path)
        let fd=url.lastPathComponent.withCString { openat(parent.fd,$0,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { throw SweepError.incomplete("无法核对内部读取程序权限") };defer { as_close(fd) }
        var raw=ASIdentity()
        guard as_identity_fd(fd,&raw) == 0, FileIdentity(raw) == snapshot.identity,
              as_unshared_node_descriptor(fd,snapshot.identity.owner) == 1 else { throw SweepError.denied("内部读取程序的权限或ACL未确认") }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL,[],&code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate | kSecCSCheckAllArchitectures),nil) == errSecSuccess else { throw SweepError.denied("内部读取程序代码签名无效") }
        try SafeFilesystem.verify(snapshot)
        return snapshot
    }
}
#endif
