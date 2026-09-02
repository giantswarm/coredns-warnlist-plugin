# Repo-owned overrides for the devctl-generated Makefile.gen.go.mk (read last
# because "zzz" sorts after "gen"). devctl never touches this file.
#
# The module root is the CoreDNS plugin library; the server main lives in
# ./cmd/coredns. The generated targets default MAIN_SOURCE to main.go, which
# does not exist here. Recipes expand variables at run time, so reassigning it
# redirects build/install/run without redefining any recipe.
MAIN_SOURCE := ./cmd/coredns
