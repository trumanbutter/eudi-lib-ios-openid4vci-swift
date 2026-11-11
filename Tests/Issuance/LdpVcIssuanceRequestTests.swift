/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import XCTest
@testable import OpenID4VCI
import SwiftyJSON

/// IBM: tests for building an `ldp_vc` (W3C JSON-LD, Data Integrity) issuance request
/// and for parsing a JSON-LD object credential response.
final class LdpVcIssuanceRequestTests: XCTestCase {

  private let configurationId = "2:ldp_vc:01a1a95b-b22f-7219-9fd6-d5811455ef06"

  private func makeConfiguration() throws -> W3CJsonLdDataIntegrityFormat.CredentialConfiguration {
    // The empty binding list mirrors the sample issuer's unbound ldp_vc configuration.
    let json = JSON(parseJSON: """
    {
      "format": "ldp_vc",
      "cryptographic_binding_methods_supported": [],
      "credential_signing_alg_values_supported": [],
      "credential_metadata": {},
      "@context": [],
      "type": [],
      "credential_definition": {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "PermanentResidentCard"]
      }
    }
    """)
    return try W3CJsonLdDataIntegrityFormat.CredentialConfiguration(json: json)
  }

  private func makeRequest(
    payload: IssuanceRequestPayload
  ) throws -> SingleCredential {
    let request = try makeConfiguration().toIssuanceRequest(
      responseEncryptionSpec: nil,
      requestPayload: payload,
      proofs: []
    )
    guard case .single(let single, _) = request else {
      XCTFail("Expected a single credential request")
      throw ValidationError.error(reason: "unexpected request")
    }
    return single
  }

  func testConfigurationBasedPayloadHasNoProofs() throws {
    let id = try CredentialConfigurationIdentifier(value: configurationId)
    let single = try makeRequest(payload: .configurationBased(credentialConfigurationIdentifier: id))

    guard case .w3CJsonLdDataIntegrity = single else {
      return XCTFail("Expected the w3CJsonLdDataIntegrity case")
    }
    XCTAssertEqual(single.credentialConfigurationIdentifier, id)
    XCTAssertTrue(single.proofs.isEmpty)

    let payload = try single.toPayload()
    XCTAssertEqual(payload["credential_configuration_id"].string, configurationId)
    XCTAssertFalse(payload["proofs"].exists())
    XCTAssertFalse(payload["credential_identifier"].exists())
  }

  func testIdentifierBasedPayloadHasNoProofs() throws {
    let id = try CredentialConfigurationIdentifier(value: configurationId)
    let credentialId = try CredentialIdentifier(value: "cred-123")
    let single = try makeRequest(
      payload: .identifierBased(
        credentialConfigurationIdentifier: id,
        credentialIdentifier: credentialId
      )
    )

    XCTAssertEqual(single.credentialConfigurationIdentifier, id)

    let payload = try single.toPayload()
    XCTAssertEqual(payload["credential_identifier"].string, "cred-123")
    XCTAssertFalse(payload["proofs"].exists())
    XCTAssertFalse(payload["credential_configuration_id"].exists())
  }

  func testObjectCredentialResponseIsParsedAsJson() throws {
    let body = """
    {
      "credential": {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "PermanentResidentCard"],
        "issuer": "https://issuer.example.com"
      }
    }
    """
    let response = try JSONDecoder().decode(
      SingleIssuanceSuccessResponse.self,
      from: Data(body.utf8)
    )

    let domain = try response.toDomain()
    guard case .issued(_, let credential, _, _) = domain.credentialResponses.first else {
      return XCTFail("Expected an issued credential")
    }
    guard case .json(let json) = credential else {
      return XCTFail("Expected a JSON credential")
    }
    XCTAssertEqual(json["issuer"].string, "https://issuer.example.com")
    XCTAssertEqual(json["type"].arrayValue.map(\.stringValue), ["VerifiableCredential", "PermanentResidentCard"])
  }

  func testStringCredentialResponseIsStillParsedAsString() throws {
    let response = try JSONDecoder().decode(
      SingleIssuanceSuccessResponse.self,
      from: Data(#"{"credential": "abc.def.ghi"}"#.utf8)
    )

    let domain = try response.toDomain()
    guard case .issued(_, let credential, _, _) = domain.credentialResponses.first,
          case .string(let value) = credential else {
      return XCTFail("Expected a string credential")
    }
    XCTAssertEqual(value, "abc.def.ghi")
  }
}
