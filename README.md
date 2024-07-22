# Goffloader - A pure Go implementation of an in-memory COFFLoader (and PE loader)

More details coming soon!

# Acknowledgements

* Ne0nD0g's [go-coff project](https://github.com/Ne0nd0g/go-coff/tree/dev)
    * Didn't realize this the dev branch of go-coff was actually filled in when this project was started. The Golang implementation of Beacon functions was the base for the `lighthouse` code along with the idea to use windows.NewCallback to avoid CGO.
* TrustedSec's [COFFLoader blogpost](https://trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs)
* OtterHacker's EXCELLENT [COFFLoader blogpost](https://otterhacker.github.io/Malware/CoffLoader.html)
* Fortra's [No-Consolation BOF](https://github.com/fortra/No-Consolation)
* The developers of the [(now-archived) Go pecoff library](https://github.com/RIscRIpt/pecoff).