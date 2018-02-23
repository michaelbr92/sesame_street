# sesame_street
Radare2 wrapper and tools

## Example
```python
r2 = R2('/bin/ls')

for string in r2.strings("help"):
    print(string.string)

func = r2.functions()[-2]
print(func.name) # prints 'fcn.00015850'
func.name = "r_my_name"
print(func.name) # prints 'r_my_name'
```
