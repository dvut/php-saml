<?php
  require 'xmlsec.php';

  /**
   * Parse the SAML response and maintain the XML for it.
   */
  class SamlResponse {
    /**
     * A SamlResponse class provided to the constructor.
     */
    private $settings;

    /**
     * The decoded, unprocessed XML assertion provided to the constructor.
     */
    public $assertion;

    /**
     * A DOMDocument class loaded from the $assertion.
     */
    public $xml;

    /**
     * Construct the response object.
     *
     * @param SamlResponse $settings
     *   A SamlResponse settings object containing the necessary
     *   x509 certicate to decode the XML.
     * @param string $assertion
     *   A UUEncoded SAML assertion from the IdP.
     */
    function __construct($settings, $assertion) {
      $this->settings = $settings;
      $this->assertion = base64_decode($assertion);
      $this->xml = new DOMDocument();
      $this->xml->loadXML($this->assertion);
    }

    /**
     * Determine if the SAML Response is valid using the certificate.
     *
     * @return
     *   TRUE if the document passes. This could throw a generic Exception
     *   if the document or key cannot be found.
     */
    function is_valid() {
      $xmlsec = new SamlXmlSec($this->settings, $this->xml);
      return $xmlsec->is_valid();
    }

    /**
     * Get the NameID provided by the SAML response from the IdP.
     */
    function get_nameid() {
      $xpath = new DOMXPath($this->xml);
      $xpath->registerNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");
      $xpath->registerNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
      $query = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";

      $entries = $xpath->query($query);
      return $entries->item(0)->nodeValue;
    }

    /**
     * Get the attributes provided by the SAML response from the IdP.
     * @return
     *   An array, the keys contain the attribute names, the values contain arrays of attribute values
     */
    function get_attributes() {
      $attributes = array();

      $xpath = new DOMXPath($this->xml);
      $xpath->registerNamespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol");
      $xpath->registerNamespace("saml","urn:oasis:names:tc:SAML:2.0:assertion");
      $query = "/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute";

      $attributeNodes = $xpath->query($query);
      foreach($attributeNodes as $attributeNode) {
        $attributeName = $attributeNode->getAttribute("Name");

        $attributeValues = array();
        $attributeValueNodes = $attributeNode->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeValue');
        foreach($attributeValueNodes as $attributeValueNode) {
          $attributeValues[] = $attributeValueNode->nodeValue;
        }

        $attributes[$attributeName] = $attributeValues;
      }

      return $attributes;
    }
  }