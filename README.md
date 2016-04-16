# Validation Discovery (KSValidationService)

DRAFT / ALPHA

Baseline code to build a validation cache (to provide validation services).  

* Why would you want a validation cache? 
  * In a large bridged Public Key Infrastructure environment, you typically want to identify all possible intermediate certificate authorities to use in seeding validation services such as SCVP, localized OCSP responders, or static Trust stores in applications that are non-RFC 5280 aware to enable certificate path building.  
  * Identifying the certificate authorities from a Root downward is performed using SIA chases. 
  * Identifying the certificate authorities from an end entity upward is performed using AIA chases. 
  
* Does this code help me identify ALL the OCSP and CRL endpoints that may be available? 
  * No.  This code cannot identify the final End Entity certificates (TLS, Person, etc) as these aren't discoverable via SIA from the final issuing certificate authority.  Therefore, the end entity certificates may have additional OCSP(AIA) and CRL(CDP) 


I make no claims that this code is right or wrong, good or bad.  I've had it on the backburner for a while, and figured I should at least share.  It is built on an older version of the BouncyCastle API, and should be updated.

## Outputs

* Performs SIA discovery using COMMON (Federal Common Policy CA) as the root certificate
* Uses discovered objects from SIA (down from root) 
  * Currently does not recurse to perform AIA from those discovered objects (TODO comment in code)
* Outputs all certificates discovered in PEM form, and an HTML log showing results including timing transactions for P7B(AIA) and CRL(CDP) URIs identified in the certificates

No warranties made on prettiness of the outputs!  Screenshot sample:

![Screenshot of HTML Output](/screenshot_html_output.PNG)

## Using

* Deploy as war in J2EE application server (i.e. Apache Tomcat)
* Tested on Tomcat 7
* Please note: the CRL files WILL be fetched. Some of these files are greater than 30 MB.  Rapid redeployments may impact I/O costs.
* Refreshing the URL that displays the validation cache has no effect. To reset the cache (at the moment) you need to _restart_ the app


