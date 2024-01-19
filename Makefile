all:
	$(MAKE) -C tem
	$(MAKE) -C tapir-cli

clean:
	@rm -f *~
	$(MAKE) clean -C tem
	$(MAKE) clean -C tapir-cli
	
.PHONY: build clean
