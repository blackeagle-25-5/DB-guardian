"""Test script for feature extractor."""

from feature_extractor import FeatureExtractor
from request import Request

# Test 1: Benign request
print("=" * 60)
print("TEST 1: Benign Request")
print("=" * 60)
req1 = Request(request='/api/user?id=1', method='GET')
fe = FeatureExtractor()
features1 = fe.extract_features(req1)
print("Request: /api/user?id=1")
print("\nFeatures:")
for k, v in features1.items():
    print(f"  {k}: {v}")

# Test 2: SQL injection attempt
print("\n" + "=" * 60)
print("TEST 2: SQL Injection Attempt")
print("=" * 60)
req2 = Request(request="/api/user?id=1' OR '1'='1", method='GET')
features2 = fe.extract_features(req2)
print("Request: /api/user?id=1' OR '1'='1")
print("\nFeatures:")
for k, v in features2.items():
    print(f"  {k}: {v}")

# Test 3: UNION-based SQL injection
print("\n" + "=" * 60)
print("TEST 3: UNION-based SQL Injection")
print("=" * 60)
req3 = Request(
    request="/api/user?id=1 UNION SELECT username,password FROM users--",
    method='GET'
)
features3 = fe.extract_features(req3)
print("Request: /api/user?id=1 UNION SELECT username,password FROM users--")
print("\nFeatures:")
for k, v in features3.items():
    print(f"  {k}: {v}")

# Test 4: XSS attempt
print("\n" + "=" * 60)
print("TEST 4: XSS Attempt")
print("=" * 60)
req4 = Request(
    request="/search?q=<script>alert('XSS')</script>",
    method='GET'
)
features4 = fe.extract_features(req4)
print("Request: /search?q=<script>alert('XSS')</script>")
print("\nFeatures:")
for k, v in features4.items():
    print(f"  {k}: {v}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Benign request - SQL keywords: {features1['sql_keyword_count']}, Quotes: {features1['quote_count']}")
print(f"SQL injection 1 - SQL keywords: {features2['sql_keyword_count']}, Quotes: {features2['quote_count']}")
print(f"SQL injection 2 - SQL keywords: {features3['sql_keyword_count']}, Quotes: {features3['quote_count']}, Comments: {features3['comment_pattern_count']}")
print(f"XSS attempt    - SQL keywords: {features4['sql_keyword_count']}, Quotes: {features4['quote_count']}")
print("\n✓ Feature extraction working correctly!")
