import Foundation

/// Discovery locations and semantics, not a deletion allowlist. Executable
/// formats are independently registered by ToolCacheRule.
enum ToolCacheCatalog {
    static let rule = "development-tool-discovery-only-v1"
    struct Entry {
        let path: String
        let title: String
        let reason: String
    }
    static func entries(home: String) -> [Entry] {
        let entries: [(String,String,String)] = [
            ("/Library/Caches/trivy","Trivy 工具缓存","仅已验证的漏洞数据库下载可处理，扫描数据库与未知内容保留"),
            ("/.npm/_cacache","npm 下载缓存","仅已验证的内容与索引格式可处理，其他内容保留"),
            ("/.npm/_npx","npm 临时工具环境","可能仍被工具使用，需要独立核对，保留"),
            ("/Library/Caches/pnpm","pnpm 元数据与工具缓存","仅已验证的注册表元数据可处理，工具环境与未知格式保留"),
            ("/Library/pnpm/store","pnpm 共享包存储","多个项目可能引用包存储，需由 pnpm 核对未使用内容，保留"),
            ("/.pnpm-store","pnpm 共享包存储","多个项目可能引用包存储，需由 pnpm 核对未使用内容，保留"),
            ("/.cache/pnpm","pnpm 缓存","此位置和版本尚未完成独立再生成验证，保留"),
            ("/.cargo/registry/cache","Cargo 下载缓存","已发现工具下载缓存，独立活动与恢复规则尚未验证，保留"),
            ("/.cargo/registry/index","Cargo 注册表索引","已发现工具索引，需独立核对使用状态与恢复，保留"),
            ("/go/pkg/mod/cache","Go 模块下载缓存","已发现模块缓存，独立执行规则尚未验证，保留"),
            ("/.cache/uv","uv 缓存","uv 要求使用自身缓存管理；目录可能被环境引用，保留"),
            ("/Library/Caches/electron","Electron 下载缓存","仅已验证的完整运行时下载可处理，未知内容保留"),
            ("/Library/Caches/electron-builder","electron-builder 工具缓存","仅已验证的工具下载可处理，Wine 环境状态与未知内容保留"),
            ("/Library/Caches/node-gyp","node-gyp 头文件缓存","已发现工具缓存，独立执行规则尚未验证，保留"),
            ("/Library/Caches/ms-playwright","Playwright 浏览器下载","可能由项目或常驻服务直接运行，不能默认作为垃圾移除"),
            ("/Library/Caches/org.swift.swiftpm","SwiftPM 缓存","已发现依赖缓存，独立执行规则尚未验证，保留")
        ]
        return entries.map { Entry(path: home + $0.0, title: $0.1, reason: $0.2) }
    }
}
