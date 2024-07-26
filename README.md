# Goffloader - A pure Go implementation of an in-memory COFFLoader (and PE loader)

Goffloader is a library that allows easy in-memory execution of [Cobalt Strike BOFs](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) and unmanaged PE files. 

# Example Usage

Goffloader is designed to make loading of BOFs or PE files as straightforward as possible by using the `go:embed` tag. For example, to run an embedded executable and display its console output the code is:

```go
import "github.com/praetorian-inc/goffloader/src/pe"

//go:embed hello.exe
var helloBytes []byte

func main() {
	output, _ := pe.RunExecutable(helloBytes, []string{"Arg1", "Arg2", "Arg3"})
	fmt.Println(output)
}
```

Full examples for running [BOFs](https://github.com/praetorian-inc/goffloader/blob/main/cmd/bof_example/whois_bof.go) or [PE files](https://github.com/praetorian-inc/goffloader/blob/main/cmd/pe_example/hello_pe.go) can be found in the `cmd` folder. The ability to run PE files is enabled via the [No-Consolation BOF](https://github.com/fortra/No-Consolation), and an example of executing that can be seen [here](https://github.com/praetorian-inc/goffloader/blob/main/src/pe/pe_windows.go)

# Why?

Given that there's already a number of very excellent C implementations of this functionality, why do this in Go?

1. Adding BOF loading to Go expands the number of open source security projects that can be used within Go security tooling. There are [entire](https://github.com/trustedsec/CS-Situational-Awareness-BOF) [repositories](https://github.com/trustedsec/CS-Remote-OPs-BOF) of useful functionality that are now accessible for Go tools via this library.
2. While you can technically just use a C implementation of COFF loaders ([Sliver does this](https://github.com/sliverarmory/COFFLoader), for example), CGO is annoying.
3. Go is a nice language for static signature evasion. You can see [an example of us being able to run an embedded version of mimikatz](https://github.com/praetorian-inc/chariot-bas/blob/main/tests/1e247e041d7f404cbfba1a4c67d62aa4.go) without jumping through too many hoops.
4. Our [open-source breach & attack simulation](https://github.com/praetorian-inc/chariot-bas) tests are written in Go...and we wanted this functionality.

# Limitations

* Currently the COFFLoader implementation is only for x64 architecture. 32-bit support will be coming soon.
* At the moment the PE execution is just loading a BOF with hard-coded arguments - eventually a few different approaches will be supported.
* The `Beacon*` API implementation is partial - most BOFs don't use much beyond the arg parsing + output functions, but there's a chunk of `beacon.h` which still needs to be implemented. This will be done as useful BOFs are identified that rely on these APIs.
* Using this library in its current state will NOT generate a 0/N detections file on VT. Right now it's 2 or 3 detections from the usual offender false+ mills, but users should be aware of this.

# Acknowledgements

* Ne0nD0g's [go-coff project](https://github.com/Ne0nd0g/go-coff/tree/dev)
    * Didn't realize this the dev branch of go-coff was actually filled in when this project was started. The Golang implementation of Beacon functions was the base for the `lighthouse` code along with the idea to use windows.NewCallback to avoid CGO.
* TrustedSec's [COFFLoader blogpost](https://trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs)
* OtterHacker's EXCELLENT [COFFLoader blogpost](https://otterhacker.github.io/Malware/CoffLoader.html)
* Fortra's [No-Consolation BOF](https://github.com/fortra/No-Consolation)
* The developers of the [(now-archived) Go pecoff library](https://github.com/RIscRIpt/pecoff).
