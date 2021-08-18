EXT_DIR=extensions
IPT_EXTENSIONS=$(notdir $(wildcard $(EXT_DIR)/*))
CLEAN_IPT_EXTENSIONS=$(addsuffix -clean, $(IPT_EXTENSIONS))

all: $(IPT_EXTENSIONS)

clean: $(CLEAN_IPT_EXTENSIONS)

$(IPT_EXTENSIONS):
	make -C $(EXT_DIR)/$@ all
	mkdir -p out/$@
	cp $(EXT_DIR)/$@/*.ko out/$@
	cp $(EXT_DIR)/$@/*.so out/$@

$(CLEAN_IPT_EXTENSIONS):
	make -C ${EXT_DIR}/$(@:-clean=) clean
	rm -rf out/$(@:-clean=)
