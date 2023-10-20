//
//  ContentView.swift
//  dwiki-bypass-poc
//
//  Created by dwiki on 20/10/23.
//

import SwiftUI
import LocalAuthentication

struct ContentView: View {
    @State private var unlocked = false
    @State private var text = "LOCKED"
    
    var body: some View {
        VStack {
            Text(text)
                .bold()
            .padding()
            
            Button("Authenticate Local Auth") {
                authenticate()
//                authenticateWithKeychain()
            }
            
            Button("Create pass auth with keychain") {
                createEntryAuthKeyChain()
            }
            
            Button("Read pass auth with keychain") {
                readEntryAuthKeyChain()
            }
        }
    }
    
    func authenticate() {
        let context = LAContext()
        var error: NSError?

        // Check whether it's possible to use biometric authentication
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {

            // Handle events
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "This is a security check reason.") { success, authenticationError in
                
                if success {
                    text = "UNLOCKED"
                } else {
                    text = "There was a problem!"
                }
            }
        } else {
            text = "Phone does not have biometrics"
        }
    }
    

    
    func createEntryAuthKeyChain(){
        let context = LAContext()
        let reason = "This is a security check reason."
        var error: Unmanaged<CFError>?

        // Create a new access control object that requires biometric authentication
        let accessControl: SecAccessControl
        if #available(iOS 11.3, *) {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error)!
        } else if #available(iOS 14.4, *) {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error)!
        } else {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryAny, &error)!
        }

        // Delete any existing keychain item with the same service and account
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "MyService",
            kSecAttrAccount as String: "MyAccount"
        ]
        let status = SecItemDelete(query as CFDictionary)

        print(status,"<< status")
        
        if status == errSecSuccess {
            text = "Previous entry deleted"
        }
        // Create a password to store in the keychain
        let password = "MyPassword".data(using: .utf8)!
        let queryPass: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "MyService",
            kSecAttrAccount as String: "MyAccount",
            kSecValueData as String: password,
            kSecAttrAccessControl as String: accessControl
        ]

        // Add the password to the keychain
        let statusNew = SecItemAdd(queryPass as CFDictionary, nil)

        // Check the result of the keychain operation
        if statusNew == errSecSuccess {
            text = "Password added to keychain"
        } else if statusNew == errSecUserCanceled {
            text = "User canceled authentication"
        } else if statusNew == errSecInteractionNotAllowed {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    // Try to add the password to the keychain again
                    let status = SecItemAdd(query as CFDictionary, nil)
                    if status == errSecSuccess {
                        text = "Password added to keychain"
                    } else {
                        text = "There was a problem one!"
                    }
                } else {
                    text = "Authentication failed"
                }
            }
        } else {
            text = "There was a problem two!"
        }
        
    }
    
    func readEntryAuthKeyChain() {
        let context = LAContext()
        let reason = "This is a security check reason."
        var error: Unmanaged<CFError>?

        // Create a new access control object that requires biometric authentication
        let accessControl: SecAccessControl
        if #available(iOS 11.3, *) {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error)!
        } else if #available(iOS 14.4, *) {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error)!
        } else {
            accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryAny, &error)!
        }

        // Create a query dictionary for the keychain item
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "MyService",
            kSecAttrAccount as String: "MyAccount",
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecAttrAccessControl as String: accessControl
        ]

        // Try to read the keychain item
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        print(status,"<< status read keychain")
        // Check the result of the keychain operation
        if status == errSecSuccess {
            let passwordData = item as! Data
            let password = String(data: passwordData, encoding: .utf8)!
            text = "Password: \(password)"
        } else if status == errSecUserCanceled {
            text = "User canceled authentication"
        } else if status == errSecInteractionNotAllowed {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    // Try to read the keychain item again
                    var item: CFTypeRef?
                    let status = SecItemCopyMatching(query as CFDictionary, &item)
                    if status == errSecSuccess {
                        let passwordData = item as! Data
                        let password = String(data: passwordData, encoding: .utf8)!
                        text = "Password: \(password)"
                    } else {
                        text = "There was a problem read one!"
                    }
                } else {
                    text = "Authentication failed"
                }
            }
        } else {
            text = "There was a problem read two!"
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
