
```python
pip install pipenv
pipenv install --ignore-pipfile
```

##### Add your API key to a secrets file (don't forget to add it to your .gitignore)...

```python
# secrets.py contents...

# VirusTotal API key
vt_key = "your_API_key"

```
```python
pipenv shell
python virustotal.py -u http://www.someexample.com https://anotherexample.com
exit
```


```python
# See argparse comment above
pipenv run python virustotal.py -uf path/to/url/file.csv
```

