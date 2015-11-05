
.PHONY: all
all:

MSC_SRCS = tee_invoke.msc irq.msc fiq.msc irq_fiq.msc

PNGS += $(MSC_SRCS:.msc=.png)

# Disable all builtin rules
.SUFFIXES:
.SUFFIXES: .png .msc

all: $(PNGS)

%.png : %.msc
	mscgen -T png $<

.PHONY: clean
clean:
	rm -f $(PNGS)
