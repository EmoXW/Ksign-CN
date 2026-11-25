//
//  SSLConfiguration.swift
//  Ksign
//
//  Centralised configuration and lifecycle handling for the local installer's
//  TLS material (server.crt / server.pem / commonName.txt).
//

import Foundation
import OSLog
import Security

// MARK: - Configuration
enum SSLConfiguration {
	/// UserDefaults key holding the user supplied certificate pack URL.
	static let packURLKey = "Feather.sslPackURL"

	/// Default certificate pack used when the user has not supplied one.
	static let defaultPackURL = "https://www.emoxw.cn/upload/pack.json"

	/// Gate so the automatic refresh runs at most once per launch.
	private static let autoRefreshAttemptedKey = "Feather.sslAutoRefreshAttempted"

	/// Certificate files consumed by `ServerInstaller`.
	static let certificateFileNames = ["server.crt", "server.pem", "commonName.txt"]

	/// Refresh the certificate when it expires within this many days.
	static let refreshThresholdDays = 14

	/// Effective certificate pack URL.
	static var packURL: String {
		let stored = UserDefaults.standard.string(forKey: packURLKey)?
			.trimmingCharacters(in: .whitespacesAndNewlines)

		guard let stored, !stored.isEmpty, URL(string: stored) != nil else {
			return defaultPackURL
		}

		return stored
	}

	/// Directory the certificate files are written to and read from.
	static var serverDirectory: URL {
		URL.documentsDirectory.appendingPathComponent("App").appendingPathComponent("Server")
	}
}

// MARK: - Certificate state
extension SSLConfiguration {
	/// Expiry date of the installed leaf certificate, if it can be read.
	static var installedExpiry: Date? {
		guard
			let url = ServerInstaller.getUrl("server", ext: "crt"),
			let data = try? Data(contentsOf: url)
		else {
			return nil
		}

		return leafExpiryDate(ofPEMData: data)
	}

	/// `true` when a usable leaf certificate is present and still valid.
	static var hasValidCertificate: Bool {
		guard let expiry = installedExpiry else { return false }
		return expiry > Date()
	}

	/// `true` when the certificate is missing or expires within `refreshThresholdDays`.
	static var needsRefresh: Bool {
		guard let expiry = installedExpiry else { return true }
		let threshold = Date().addingTimeInterval(TimeInterval(refreshThresholdDays) * 86_400)
		return expiry <= threshold
	}

	/// `true` while any of the certificate files has not been staged yet.
	static var isMissingCertificateFiles: Bool {
		let manager = FileManager.default
		return certificateFileNames.contains {
			!manager.fileExists(atPath: serverDirectory.appendingPathComponent($0).path)
		}
	}
}

// MARK: - Staging
extension SSLConfiguration {
	/// Copies the bundled fallback certificates into Documents.
	///
	/// Existing files are **never** replaced: a certificate obtained from the
	/// remote pack is authoritative, and overwriting it on every launch was the
	/// reason renewed certificates stopped working after a restart.
	static func stageBundledCertificatesIfNeeded() {
		let manager = FileManager.default
		try? manager.createDirectoryIfNeeded(at: serverDirectory)

		for fileName in certificateFileNames {
			let destination = serverDirectory.appendingPathComponent(fileName)
			guard !manager.fileExists(atPath: destination.path) else { continue }

			let name = (fileName as NSString).deletingPathExtension
			let ext = (fileName as NSString).pathExtension

			guard let bundled = Bundle.main.url(forResource: name, withExtension: ext) else {
				continue
			}

			try? manager.copyItem(at: bundled, to: destination)
		}
	}
}

// MARK: - Refresh
extension SSLConfiguration {
	/// Downloads the certificate pack once per launch when the installed
	/// certificate is missing or about to expire.
	static func refreshIfNeeded() {
		guard !UserDefaults.standard.bool(forKey: autoRefreshAttemptedKey) else { return }
		UserDefaults.standard.set(true, forKey: autoRefreshAttemptedKey)

		guard needsRefresh else { return }

		FR.downloadSSLCertificates(from: packURL) { success in
			if !success {
				Logger.misc.warning("SSL certificate refresh failed")
			}
		}
	}

	/// Forces a download, ignoring the once-per-launch gate.
	static func refresh(completion: @escaping (Bool) -> Void) {
		FR.downloadSSLCertificates(from: packURL, completion: completion)
	}
}

// MARK: - PEM / DER parsing
extension SSLConfiguration {
	/// Reads `notAfter` from the first certificate in a PEM bundle.
	///
	/// `server.crt` is a PEM chain whose first entry is the leaf certificate,
	/// so only that block carries the expiry that matters for refresh timing.
	static func leafExpiryDate(ofPEMData data: Data) -> Date? {
		guard
			let text = String(data: data, encoding: .utf8),
			let begin = text.range(of: "-----BEGIN CERTIFICATE-----"),
			let end = text.range(
				of: "-----END CERTIFICATE-----",
				range: begin.upperBound..<text.endIndex
			)
		else {
			return nil
		}

		let block = String(text[begin.lowerBound..<end.upperBound])
		guard let der = derData(fromPEM: block) else { return nil }

		return DERReader(bytes: [UInt8](der)).notAfterDate()
	}

	/// Strips PEM armour and base64-decodes the certificate body.
	private static func derData(fromPEM pem: String) -> Data? {
		let base64 = pem
			.components(separatedBy: .newlines)
			.filter { !$0.hasPrefix("-----") }
			.joined()
			.trimmingCharacters(in: .whitespacesAndNewlines)

		return Data(base64Encoded: base64)
	}
}

/// Minimal DER reader: just enough ASN.1 to reach `Validity.notAfter`.
///
/// `SecCertificateCopyValues` is unavailable on iOS, so the validity window is
/// read straight from the certificate structure:
/// `Certificate → TBSCertificate → Validity → [notBefore, notAfter]`.
private struct DERReader {
	let bytes: [UInt8]

	private struct Node {
		let tag: UInt8
		let start: Int
		let end: Int
	}

	/// Reads the TLV whose header starts at `offset`.
	private func node(at offset: Int) -> Node? {
		guard offset >= 0, offset < bytes.count else { return nil }

		let tag = bytes[offset]
		var cursor = offset + 1
		guard cursor < bytes.count else { return nil }

		var length = Int(bytes[cursor])
		cursor += 1

		if length & 0x80 != 0 {
			let byteCount = length & 0x7F
			guard byteCount > 0, byteCount <= 4, cursor + byteCount <= bytes.count else {
				return nil
			}

			length = 0
			for _ in 0..<byteCount {
				length = (length << 8) | Int(bytes[cursor])
				cursor += 1
			}
		}

		let end = cursor + length
		guard end <= bytes.count, end >= cursor else { return nil }

		return Node(tag: tag, start: cursor, end: end)
	}

	func notAfterDate() -> Date? {
		// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
		guard let certificate = node(at: 0), certificate.tag == 0x30 else { return nil }

		// TBSCertificate is the first element of Certificate.
		guard let tbs = node(at: certificate.start), tbs.tag == 0x30 else { return nil }

		// Walk TBSCertificate children and pick the Validity SEQUENCE, which is
		// the only inner SEQUENCE whose first element is a time value.
		var cursor = tbs.start
		var validity: Node?

		while cursor < tbs.end, let child = node(at: cursor) {
			if child.tag == 0x30,
			   let first = node(at: child.start),
			   first.tag == 0x17 || first.tag == 0x18 {
				validity = child
				break
			}
			cursor = child.end
		}

		guard let validity else { return nil }

		// Validity ::= SEQUENCE { notBefore Time, notAfter Time }
		guard
			let notBefore = node(at: validity.start),
			notBefore.end <= validity.end,
			let notAfter = node(at: notBefore.end),
			notAfter.end <= validity.end
		else {
			return nil
		}

		return Self.date(tag: notAfter.tag, bytes: Array(bytes[notAfter.start..<notAfter.end]))
	}

	private static func date(tag: UInt8, bytes: [UInt8]) -> Date? {
		guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }

		let formatter = DateFormatter()
		formatter.locale = Locale(identifier: "en_US_POSIX")
		formatter.timeZone = TimeZone(secondsFromGMT: 0)

		switch tag {
		case 0x17: // UTCTime — "YYMMDDHHMMSSZ", two digit year
			guard text.count >= 11 else { return nil }
			formatter.dateFormat = "yyMMddHHmmss'Z'"
		case 0x18: // GeneralizedTime — "YYYYMMDDHHMMSSZ"
			formatter.dateFormat = "yyyyMMddHHmmss'Z'"
		default:
			return nil
		}

		let digits = text.hasSuffix("Z") ? text : text + "Z"
		return formatter.date(from: digits)
	}
}
