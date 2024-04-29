# doubles  
## find duplicate files on given paths  

Usage of doubles:  
`doubles [OPTIONS] PATH_1 PATH_2 ... PATH_N`  
### Options:
```
  -calc
    	calculate wasted space (default true)
  -hash-func string
    	hash function (md5|sha1|sha256|sha512) (default "md5")
  -no-errors
    	suppress error messages
  -p value
    	pattern for file names (https://pkg.go.dev/path/filepath#Match) (shorthand)
  -pattern value
    	pattern for file names (https://pkg.go.dev/path/filepath#Match)
  -s	show file sizes (shorthand) (default true)
  -show-sizes
    	show file sizes (default true)
  -skip-zero
    	skip zero-sized files (default true)
```
