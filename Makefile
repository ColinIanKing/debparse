CFLAGS += -Wall -O2 -g
LDFLAGS +=
SOURCES = debparse.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = debparse
LIBS = -larchive

all: $(SOURCES) $(TARGET)

ifeq ($(PEDANTIC),1)
CFLAGS += \
	-Wextra \
	-Wfloat-equal \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wno-long-long -Wpacked \
	-Wredundant-decls \
	-Wshadow \
	-Wno-missing-field-initializers \
	-Wno-missing-braces \
	-Wno-sign-compare \
	-Wno-multichar
endif

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -larchive -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
