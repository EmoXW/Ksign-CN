//
//  ServerView.swift
//  Feather
//
//  Created by samara on 6.05.2025.
//

import SwiftUI
import NimbleJSON
import NimbleViews

struct ServerView: View {
	@AppStorage("Feather.ipFix") private var _ipFix: Bool = false
	@AppStorage("Feather.serverMethod") private var _serverMethod: Int = 1

	@AppStorage(SSLConfiguration.packURLKey) private var _packURL: String = ""
	@State private var _packURLEditing: String = ""
	@State private var _isEditingPackURL: Bool = false
	@State private var _isDownloading: Bool = false
	@State private var _installedExpiry: Date?

	private let _serverMethods: [String] = [
		.localized("Fully Local"),
		.localized("Semi Local")
	]

	var body: some View {
		Group {
			Section {
				Picker(.localized("Installation Type"), systemImage: "server.rack", selection: $_serverMethod) {
					ForEach(_serverMethods.indices, id: \.self) { index in
						Text(_serverMethods[index]).tag(index)
					}
				}
				Toggle(.localized("Only use localhost address"), systemImage: "lifepreserver", isOn: $_ipFix)
					.disabled(_serverMethod != 1)
			}

			Section {
				Button(.localized("Update SSL Certificates"), systemImage: "arrow.down.doc") {
					_download()
				}
				.disabled(_isDownloading)

				if _isDownloading {
					HStack(spacing: 8) {
						ProgressView()
						Text(.localized("Downloading"))
							.foregroundColor(.secondary)
					}
				}
			} footer: {
				Text(_statusFooter)
			}

			Section {
				if _isEditingPackURL {
					TextField(.localized("Enter URL"), text: $_packURLEditing)
						.textInputAutocapitalization(.never)
						.autocorrectionDisabled()
						.keyboardType(.URL)

					Button(.localized("Save")) {
						let trimmed = _packURLEditing.trimmingCharacters(in: .whitespacesAndNewlines)
						_packURL = trimmed
						_isEditingPackURL = false
						_refreshStatus()
					}
					.disabled(URL(string: _packURLEditing.trimmingCharacters(in: .whitespacesAndNewlines)) == nil)

					Button(.localized("Cancel"), role: .cancel) {
						_isEditingPackURL = false
						_packURLEditing = _packURL
					}
				} else {
					Button(.localized("Change")) {
						_packURLEditing = SSLConfiguration.packURL
						_isEditingPackURL = true
					}

					Button(.localized("Reset")) {
						_packURL = ""
						_refreshStatus()
					}
					.disabled(_packURL.isEmpty)
				}
			} header: {
				Text(.localized("SSL Certificates"))
			} footer: {
				Text(SSLConfiguration.packURL)
					.font(.footnote)
					.textSelection(.enabled)
			}
		}
		.onAppear(perform: _refreshStatus)
		.onChange(of: _serverMethod) { _ in			UIAlertController.showAlertWithRestart(
				title: .localized("Restart Required"),
				message: .localized("These changes require a restart of the app")
			)
		}
	}
}

// MARK: - Extension: actions
extension ServerView {
	private var _statusFooter: String {
		guard let expiry = _installedExpiry else {
			return .localized("No certificate installed, tap Update SSL Certificates to download one.")
		}

		let formatter = DateFormatter()
		formatter.dateStyle = .medium
		formatter.timeStyle = .none

		let date = formatter.string(from: expiry)

		if expiry <= Date() {
			return .localized("Certificate expired on %@, please update it.", arguments: date)
		}

		if SSLConfiguration.needsRefresh {
			return .localized("Certificate expires on %@, please update it soon.", arguments: date)
		}

		return .localized("Certificate valid until %@.", arguments: date)
	}

	private func _refreshStatus() {
		_installedExpiry = SSLConfiguration.installedExpiry
	}

	private func _download() {
		_isDownloading = true

		SSLConfiguration.refresh { success in
			DispatchQueue.main.async {
				_isDownloading = false

				if success {
					_installedExpiry = SSLConfiguration.installedExpiry
					UIAlertController.showAlertWithOk(
						title: .localized("SSL Certificates"),
						message: _statusFooter
					)
				} else {
					UIAlertController.showAlertWithOk(
						title: .localized("SSL Certificates"),
						message: .localized("Failed to download, check your internet connection and try again.")
					)
				}
			}
		}
	}
}
