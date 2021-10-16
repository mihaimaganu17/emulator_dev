SERVER = mag@192.168.0.155

all:
	scp -r ../wurst_maker $(SERVER):
	ssh $(SERVER) "\"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat\" x64 && cd wurst_maker && nmake -f Makefile.win "
