# Test Results

**Project:** EWB Phishing URL Awareness Checker  
**Python version:** 3.13 (replace with your installed version if different)  
**Operating system:** Windows  
**Date:** 7 November 2026

## Test Cases

| # | Input URL | Expected Result | Actual Result | Pass/Fail |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No warning signs detected; score 0 | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP | IP address and HTTP warnings; score 40 | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP | @ symbol and HTTP warnings; score 35 | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Hostname segment warning; score 15 | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname | Punycode warning; score 20 | PASS |


## Notes

- The program successfully identifies the selected URL warning signs in the five sample cases.
- The tests helped verify that different URL structures produce different warning messages and scores.
- A URL with no detected warning signs is not guaranteed to be safe.

## Conclusion

The five sample test cases were executed to verify the URL inspection logic. The observed results matched the expected warning signs.