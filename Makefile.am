SUBDIRS  = . src #orig
doc_DATA = AUTHORS ChangeLog NEWS README

# This is the only way with automake I know of to force 'check-git-hooks'
# to be evaluated before 'all'. If there is a nicer way, I'm all ears...
BUILT_SOURCES = install-git-hooks

###################################
# git hook management
#

install-git-hooks:
	if test -d githooks -a -d .git; then                        \
	    for hook in githooks/???* kludge~; do                   \
	        case $$hook in                                      \
	            *.sample|*~|*.swp) continue;;                   \
	        esac;                                               \
	        if test -x $$hook -a                                \
		      ! -x .git/hooks/$${hook##*/}; then            \
	            echo "Installing git hook $${hook##*/}...";     \
	            cp $$hook .git/hooks;                           \
	            chmod a+x .git/hooks/$${hook##*/};              \
	        fi                                                  \
	    done                                                    \
	fi

install-data-hook:
#	mkdir -p $(DESTDIR)/lib/systemd/system

# cleanup
clean-local:
	rm -f *~
