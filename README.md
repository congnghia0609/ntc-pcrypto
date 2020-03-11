# ntc-pcrypto
ntc-pcrypto is module python cryptography

## Installation
From pip:  
```bash
pip install ntc-pcrypto
```
From Source:  
```bash
git clone https://github.com/congnghia0609/ntc-pcrypto.git
cd ntc-pcrypto
python3 setup.py install
```

## Check version
```bash
pip show ntc-pcrypto
```

## 1. An implementation of Shamir's Secret Sharing Algorithm 256-bits in Python

### Usage
**Use encode/decode Base64**  
```python
from sss.sss import *

s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
print("secret:", s)
print("secret.length:", len(s))
# creates a set of shares
arr = create(3, 6, s, True)
# combines shares into secret
s1 = combine(arr[:3], True)
print("combines shares 1 length =", len(arr[:3]))
print("secret:", s1)
print("secret.length:", len(s1))

s2 = combine(arr[3:], True)
print("combines shares 2 length =", len(arr[3:]))
print("secret:", s2)
print("secret.length:", len(s2))

s3 = combine(arr[1:5], True)
print("combines shares 3 length =", len(arr[1:5]))
print("secret:", s3)
print("secret.length:", len(s3))
```

**Use encode/decode Hex**  
```python
from sss.sss import *

s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
print("secret:", s)
print("secret.length:", len(s))
# creates a set of shares
arr = create(3, 6, s, False)
# combines shares into secret
s1 = combine(arr[:3], False)
print("combines shares 1 length =", len(arr[:3]))
print("secret:", s1)
print("secret.length:", len(s1))

s2 = combine(arr[3:], False)
print("combines shares 2 length =", len(arr[3:]))
print("secret:", s2)
print("secret.length:", len(s2))

s3 = combine(arr[1:5], False)
print("combines shares 3 length =", len(arr[1:5]))
print("secret:", s3)
print("secret.length:", len(s3))
```

## License
This code is under the [Apache Licence v2](https://www.apache.org/licenses/LICENSE-2.0).  
