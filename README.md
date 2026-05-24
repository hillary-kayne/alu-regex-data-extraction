# ALU Regex Data Extraction

## What This Program Does
This program reads messy text files from `input/raw-text.txt` and extracts data
using regular expressions. The extracted data is validated and saved to `output/sample-output.json`.

## Data Types Extracted
- Emails (validated as ALU emails)
- Credit Card Numbers
- URLs
- Phone Numbers
- Times (12 and 24 hour formats)
- Hashtags
- Currency Amounts

## How to Run
Make sure Python 3 is already installed in your computer! Open up a terminal in the root directory
of this project, and type the following command:
```bash
python data_extraction.py
```
## Security Considerations
- The input is cleaned before processing to make sure of XSS and SQL injection protection.
- Credit card numbers have to be sort of covered in this encryption:`**** **** **** 1234`
- Emails are masked in output (`j*******@gmail.com`)
- Invalid/malformed data is rejected and not included in results
- The Luhn algorithm is used to flag fake credit card numbers
