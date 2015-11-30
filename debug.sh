killall hubicfuse
git pull origin utime
make debug
sudo umount -l /mnt/hubic
sudo make install
if [ "$?" == "0" ]; then
#hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
gdb --args hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
#gdbserver :12345 hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
#standard test
#valgrind  -v --suppressions=test/valgrind-suppressions-all.supp --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f

#generate suppresion info
#valgrind  -v --suppressions=test/valgrind-suppressions-all.supp --gen-suppressions=all --memcheck:leak-check=full --show-reachable=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f

#valgrind --tool=memcheck --leak-check=yes --track-origins=yes --leak-check=full --show-leak-kinds=all  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -d
#G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --tool=memcheck --leak-check=yes --track-origins=yes  hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other -f
else
	echo error make
fi
