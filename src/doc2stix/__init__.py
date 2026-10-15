"""doc-to-stix: threat-intelligence documents to STIX 2.1 bundles for OpenCTI."""

# 0.1  baseline: chunks of 9 000 characters, rules prompt, entities found so far
#      passed to the next chunk; Ollama with JSON-schema constrained output
# 0.2  + harvest.py: ATT&CK IDs, CVE IDs, hashes, defanged IOCs and public IPs
#      written literally are added to the model's extraction; techniques nobody
#      uses go to the document's main subject
# 0.3  an answer cut at the output limit, unparsable or aborted (repetition loop)
#      is asked again in two halves of the chunk, down to two levels; a failed
#      request no longer ends the document
ENGINE_VERSION = "0.3"
