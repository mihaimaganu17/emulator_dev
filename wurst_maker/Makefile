SERVER = m3m0ry@192.168.0.175

all:
	scp -r ../wurst_maker $(SERVER):
	ssh $(SERVER) "\"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat\" x64 && cd wurst_maker && nmake -f Makefile.win "
