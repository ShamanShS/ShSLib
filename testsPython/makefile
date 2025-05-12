
aes_test:
	rm -rf logTestAes.log
	touch logTestAes.log
	pytest testAes.py -v -s --benchmark-enable >> logTestAes.log

argon2_test:
	rm -rf logTestArgon2.log
	touch logTestArgon2.log
	pytest testArgon2.py -v -s --benchmark-enable >> logTestArgon2.log

ed25519_test:
	rm -rf logTestEd25519.log
	touch logTestEd25519.log
	pytest testEd25519.py -v -s --benchmark-enable >> logTestEd25519.log

blake2_test:
	rm -rf logTestBlake2.log
	touch logTestBlake2.log
	pytest testBlake2.py -v -s --benchmark-enable >> logTestBlake2.log

sha512_test:
	rm -rf logTestSha512.log
	touch logTestSha512.log
	pytest testSha512.py -v -s --benchmark-enable >> logTestSha512.log