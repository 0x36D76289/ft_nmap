NAME := ft_nmap
OBJDIR := obj

CC := cc
CFLAGS := -Wall -Wextra -Werror -std=c11
CPPFLAGS := -D_DEFAULT_SOURCE -D_BSD_SOURCE -Iinclude
LDLIBS := -lpcap -lpthread

SRCS := \
	src/main.c \
	src/options.c \
	src/targets.c \
	src/scanner.c \
	src/packet.c \
	src/capture.c \
	src/services.c \
	src/output.c \
	src/scans/syn.c \
	src/scans/null.c \
	src/scans/fin.c \
	src/scans/xmas.c \
	src/scans/ack.c \
	src/scans/udp.c

OBJS := $(SRCS:src/%.c=$(OBJDIR)/%.o)
DEPS := $(OBJS:.o=.d)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re

-include $(DEPS)
