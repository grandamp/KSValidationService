package org.keysupport.fpki;

import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/*
 * This class provides a lookup map in a singleton.
 * 
 * It is used to translate a string identifier to a policy OID.
 * 
 * I.e., Ask it for the policy "id-fpki-common-authentication", and
 * it will reply with the ASN1ObjectIdentifier id_fpki_common_authentication,
 * which you can call id_fpki_common_authentication.toString() to obtain
 * the identifier in String form.
 */
public class PolicyMap {

	private static PolicyMap instance = null;
	private static ConcurrentHashMap<String, ASN1ObjectIdentifier> policyMap = null;
	
	protected PolicyMap() {
		/*
		 * Create our Map
		 */
		policyMap = new ConcurrentHashMap<String, ASN1ObjectIdentifier>();
		/*
		 * Initialize with CSOR objects
		 */
		policyMap.put("aces-ca", FPKIPolicyObjectIdentifiers.aces_ca);
		policyMap.put("aces-identity", FPKIPolicyObjectIdentifiers.aces_identity);
		policyMap.put("aces-business-rep", FPKIPolicyObjectIdentifiers.aces_business_rep);
		policyMap.put("aces-relying-party", FPKIPolicyObjectIdentifiers.aces_relying_party);
		policyMap.put("aces-SSL", FPKIPolicyObjectIdentifiers.aces_ssl);
		policyMap.put("aces-fed-employee", FPKIPolicyObjectIdentifiers.aces_fed_employee);
		policyMap.put("aces-fed-employee-hw", FPKIPolicyObjectIdentifiers.aces_fed_employee_hw);
		policyMap.put("pto-registered-practitioner", FPKIPolicyObjectIdentifiers.pto_registered_practitioner);
		policyMap.put("pto-inventor", FPKIPolicyObjectIdentifiers.pto_inventor);
		policyMap.put("pto-practitioner-employee", FPKIPolicyObjectIdentifiers.pto_practitioner_employee);
		policyMap.put("pto-basic", FPKIPolicyObjectIdentifiers.pto_basic);
		policyMap.put("pto-service-provider", FPKIPolicyObjectIdentifiers.pto_service_provider);
		policyMap.put("pto-service-provider-registrar", FPKIPolicyObjectIdentifiers.pto_service_provider_registrar);
		policyMap.put("pto-basic-2003", FPKIPolicyObjectIdentifiers.pto_basic_2003);
		policyMap.put("pto-medium-2003", FPKIPolicyObjectIdentifiers.pto_medium_2003);
		policyMap.put("id-pto-mediumHardware", FPKIPolicyObjectIdentifiers.id_pto_mediumhardware);
		policyMap.put("id-pto-cardAuth", FPKIPolicyObjectIdentifiers.id_pto_cardauth);
		policyMap.put("id-fpki-certpcy-rudimentaryAssurance", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_rudimentaryassurance);
		policyMap.put("id-fpki-certpcy-basicAssurance", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_basicassurance);
		policyMap.put("id-fpki-certpcy-mediumAssurance", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumassurance);
		policyMap.put("id-fpki-certpcy-highAssurance", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_highassurance);
		policyMap.put("id-fpki-certpcy-testAssurance", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_testassurance);
		policyMap.put("id-fpki-certpcy-mediumHardware", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumhardware);
		policyMap.put("id-fpki-certpcy-medium-CBP", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_medium_cbp);
		policyMap.put("id-fpki-certpcy-mediumHW-CBP", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumhw_cbp);
		policyMap.put("id-fpki-certpcy-pivi-hardware", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_pivi_hardware);
		policyMap.put("id-fpki-certpcy-pivi-cardAuth", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_pivi_cardauth);
		policyMap.put("id-fpki-certpcy-pivi-contentSigning", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_pivi_contentsigning);
		policyMap.put("id-fpki-SHA1-medium-CBP", FPKIPolicyObjectIdentifiers.id_fpki_sha1_medium_cbp);
		policyMap.put("id-fpki-SHA1-mediumHW-CBP", FPKIPolicyObjectIdentifiers.id_fpki_sha1_mediumhw_cbp);
		policyMap.put("id-fpki-certpcy-mediumDevice", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumdevice);
		policyMap.put("id-fpki-certpcy-mediumDeviceHardware", FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumdevicehardware);
		policyMap.put("id-fpki-common-policy", FPKIPolicyObjectIdentifiers.id_fpki_common_policy);
		policyMap.put("id-fpki-common-hardware", FPKIPolicyObjectIdentifiers.id_fpki_common_hardware);
		policyMap.put("id-fpki-common-devices", FPKIPolicyObjectIdentifiers.id_fpki_common_devices);
		policyMap.put("id-fpki-common-authentication", FPKIPolicyObjectIdentifiers.id_fpki_common_authentication);
		policyMap.put("id-fpki-common-high", FPKIPolicyObjectIdentifiers.id_fpki_common_high);
		policyMap.put("id-fpki-common-cardAuth", FPKIPolicyObjectIdentifiers.id_fpki_common_cardauth);
		policyMap.put("id-fpki-SHA1-policy", FPKIPolicyObjectIdentifiers.id_fpki_sha1_policy);
		policyMap.put("id-fpki-SHA1-hardware", FPKIPolicyObjectIdentifiers.id_fpki_sha1_hardware);
		policyMap.put("id-fpki-SHA1-devices", FPKIPolicyObjectIdentifiers.id_fpki_sha1_devices);
		policyMap.put("id-fpki-SHA1-authentication", FPKIPolicyObjectIdentifiers.id_fpki_sha1_authentication);
		policyMap.put("id-fpki-SHA1-cardAuth", FPKIPolicyObjectIdentifiers.id_fpki_sha1_cardauth);
		policyMap.put("id-fpki-common-devicesHardware", FPKIPolicyObjectIdentifiers.id_fpki_common_deviceshardware);
		policyMap.put("id-fpki-common-piv-contentSigning", FPKIPolicyObjectIdentifiers.id_fpki_common_piv_contentsigning);
		policyMap.put("id-eGov-Level1", FPKIPolicyObjectIdentifiers.id_egov_level1);
		policyMap.put("id-eGov-Level2", FPKIPolicyObjectIdentifiers.id_egov_level2);
		policyMap.put("id-eGov-Applications", FPKIPolicyObjectIdentifiers.id_egov_applications);
		policyMap.put("id-eGov-Level1-IdP", FPKIPolicyObjectIdentifiers.id_egov_level1_idp);
		policyMap.put("id-eGov-Level2-IdP", FPKIPolicyObjectIdentifiers.id_egov_level2_idp);
		policyMap.put("id-eGov-Level3-IdP", FPKIPolicyObjectIdentifiers.id_egov_level3_idp);
		policyMap.put("id-eGov-Level4-IdP", FPKIPolicyObjectIdentifiers.id_egov_level4_idp);
		policyMap.put("id-eGov-BAE-Broker", FPKIPolicyObjectIdentifiers.id_egov_bae_broker);
		policyMap.put("id-eGov-RelyingParty", FPKIPolicyObjectIdentifiers.id_egov_relyingparty);
		policyMap.put("id-eGov-MetaSigner", FPKIPolicyObjectIdentifiers.id_egov_metasigner);
		policyMap.put("id-eGov-MetaSigner-Hardware", FPKIPolicyObjectIdentifiers.id_egov_metasigner_hardware);
		policyMap.put("nist-cp1", FPKIPolicyObjectIdentifiers.nist_cp1);
		policyMap.put("treasury-cp1", FPKIPolicyObjectIdentifiers.treasury_cp1);
		policyMap.put("id-treasury-certpcy-rudimentary", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_rudimentary);
		policyMap.put("id-treasury-certpcy-basicindividual", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_basicindividual);
		policyMap.put("id-treasury-certpcy-basicorganizational", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_basicorganizational);
		policyMap.put("id-treasury-certpcy-medium", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_medium);
		policyMap.put("id-treasury-certpcy-mediumhardware", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_mediumhardware);
		policyMap.put("id-treasury-certpcy-high", FPKIPolicyObjectIdentifiers.id_treasury_certpcy_high);
		policyMap.put("id-treacertpcy-internalnpe", FPKIPolicyObjectIdentifiers.id_treacertpcy_internalnpe);
		policyMap.put("id-US-IRS-Securemail", FPKIPolicyObjectIdentifiers.id_us_irs_securemail);
		//TODO: Complete this once FPKIPolicyObjectIdentifiers is complete
		//TODO: Load in properties file mappings for custom policies
	}
	
	public static synchronized PolicyMap getInstance() {
		if (instance == null) {
			instance = new PolicyMap();
		}
		return instance;
	}

	public static ASN1ObjectIdentifier getPolicyOID(String id) throws Exception {
		if (policyMap.containsKey(id)) {
			return policyMap.get(id);
		} else {
			throw new Exception("Invalid Policy");
		}		
	}

	public String getPolicyOIDString(String id) throws Exception {
		return getPolicyOID(id).toString();
	}
	
}