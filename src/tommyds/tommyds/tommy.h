/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/** \mainpage
 * \section Introduction
 * Tommy is a C library of hashtables and tries designed to store and find objects
 * with high performance.
 *
 * It's <b>faster</b> than all the similar libraries like
 * <a href="http://www.canonware.com/rb/">rbtree</a>,
 * <a href="http://judy.sourceforge.net/">judy</a>,
 * <a href="http://code.google.com/p/cpp-btree/">googlebtree</a>
 * <a href="http://panthema.net/2007/stx-btree/">stxbtree</a>,
 * <a href="http://attractivechaos.awardspace.com/">khash</a>,
 * <a href="http://uthash.sourceforge.net/">uthash</a>,
 * <a href="http://www.nedprod.com/programs/portable/nedtries/">nedtrie</a>,
 * <a href="http://code.google.com/p/judyarray/">judyarray</a>,
 * <a href="http://concurrencykit.org/">concurrencykit</a> and others.
 * Only <a href="http://code.google.com/p/google-sparsehash/">googledensehash</a> is a real competitor for Tommy.
 *
 * The data structures provided are:
 *
 * - ::tommy_list - A double linked list.
 * - ::tommy_array, ::tommy_arrayof - A linear array.
 * It doesn't fragment the heap.
 * - ::tommy_arrayblk, ::tommy_arrayblkof - A blocked linear array.
 * It doesn't fragment the heap and it minimizes the space occupation.
 * - ::tommy_hashtable - A fixed size chained hashtable.
 * - ::tommy_hashdyn - A dynamic chained hashtable.
 * - ::tommy_hashlin - A linear chained hashtable.
 * It doesn't have the problem of the delay when resizing and
 * it doesn't fragment the heap.
 * - ::tommy_trie - A trie optimized for cache utilization.
 * - ::tommy_trie_inplace - A trie completely inplace.
 *
 * The most interesting are ::tommy_array, ::tommy_hashdyn, ::tommy_hashlin, ::tommy_trie and ::tommy_trie_inplace.
 *
 * Tommy is released with a \ref license "2-clause BSD license".
 *
 * The official site of TommyDS is <a href="http://tommyds.sourceforge.net/">http://tommyds.sourceforge.net/</a>,
 *
 * \section Use
 *
 * All the Tommy containers are used to store pointers to generic objects, associated to an
 * integer value, that could be a key or a hash value.
 *
 * They are semantically equivalent at the C++ <a href="http://www.cplusplus.com/reference/map/multimap/">multimap\<unsigned,void*\></a>
 * and <a href="http://www.cplusplus.com/reference/unordered_map/unordered_multimap/">unordered_multimap\<unsigned,void*\></a>.
 *
 * An object, to be inserted in a container, should contain a node of type ::tommy_node.
 * Inside this node is present a pointer to the object itself in the tommy_node::data field,
 * the key used to identify the object in the tommy_node::key field, and other fields used
 * by the containers.
 *
 * This is a typical object declaration:
 * \code
 * struct object {
 *     tommy_node node;
 *     // other fields
 * };
 * \endcode
 *
 * To insert an object in a container, you have to provide the address of the embedded node,
 * the address of the object and the value of the key.
 * \code
 * int key_to_insert = 1;
 * struct object* obj = malloc(sizeof(struct object));
 * ...
 * tommy_trie_insert(..., &obj->node, obj, key_to_insert);
 * \endcode
 *
 * To search an object you have to provide the key and call the search function.
 * \code
 * int key_to_find = 1;
 * struct object* obj = tommy_trie_search(..., key_to_find);
 * if (obj) {
 *   // found
 * }
 * \endcode
 *
 * To access all the objects with the same keys you have to iterate over the bucket
 * assigned at the specified key.
 * \code
 * int key_to_find = 1;
 * tommy_trie_node* i = tommy_trie_bucket(..., key_to_find);
 *
 * while (i) {
 *     struct object* obj = i->data; // gets the object pointer
 *
 *     printf("%d\n", obj->value); // process the object
 *
 *     i = i->next; // goes to the next element
 * }
 * \endcode
 *
 * To remove an object you have to provide the key and call the remove function.
 * \code
 * int key_to_remove = 1;
 * struct object* obj = tommy_trie_remove(..., key_to_remove);
 * if (obj) {
 *     // found
 *     free(obj); // frees the object allocated memory
 * }
 * \endcode
 *
 * Dealing with hashtables, instead of the key, you have to provide the hash value of the object,
 * and a compare function able to differentiate objects with the same hash value.
 * To compute the hash value, you can use the generic tommy_hash_u32() function, or the
 * specialized integer hash function tommy_inthash_u32().
 *
 * \section Performance
 * Here you can see some timings comparing with other natable implementations in the <i>Hit</i>
 * and <i>Change</i> graphs. Hit means searching an object with a key with success,
 * and Change means searching, removing and reinsert it with a different key value.
 *
 * Times are expressed in nanoseconds for element, and <b>lower is better</b>.
 *
 * To have some reference numbers, you can check <a href="https://gist.github.com/jboner/2841832">Latency numbers every programmer should know</a>.
 *
 * A complete analysis is available in the \ref benchmark page.
 *
 * <img src="def/img_random_hit.png"/>
 *
 * <img src="def/img_random_change.png"/>
 *
 * \section Features
 *
 * Tommy is fast and easy to use.
 *
 * Tommy is 100% portable in all the platforms and operating systems.
 *
 * Tommy containers support multiple elements with the same key.
 *
 * See the \ref design page for more details.
 *
 * \section Limitations
 *
 * Tommy is not thread safe. You have always to provide thread safety using
 * locks before calling any Tommy functions.
 *
 * Tommy doesn't provide iterators over the implicit order defined by the data
 * structures. To iterate on elements you must insert them also into a ::tommy_list,
 * and use the list as iterator. See the \ref multiindex example for more details.
 * Note that this is a real limitation only for ::tommy_trie, as it's the only
 * data structure defining an useable order.
 *
 * Tommy doesn't provide an error reporting mechanism for a malloc() failure.
 * You have to provide it redefining malloc() if you expect it to fail.
 *
 * Tommy assumes to never have more than 2^32-1 elements in a container.
 *
 * \page benchmark Tommy Benchmarks
 *
 * To evaluate Tommy performances, an extensive benchmark was done,
 * comparing it to the best libraries of data structures available:
 *
 * Specifically we test:
 *  - ::tommy_hashtable - Fixed size chained hashtable.
 *  - ::tommy_hashdyn - Dynamic chained hashtable.
 *  - ::tommy_hashlin - Linear chained hashtable.
 *  - ::tommy_trie - Trie optimized for cache usage.
 *  - ::tommy_trie_inplace - Trie completely inplace.
 *  - <a href="http://www.canonware.com/rb/">rbtree</a> - Red-black tree by Jason Evans.
 *  - <a href="http://www.nedprod.com/programs/portable/nedtries/">nedtrie</a> - Binary trie inplace by Niall Douglas.
 *  - <a href="http://attractivechaos.awardspace.com/">khash</a> - Dynamic open addressing hashtable by Attractive Chaos.
 *  - <a href="http://uthash.sourceforge.net/">uthash</a> - Dynamic chaining hashtable by Troy D. Hanson.
 *  - <a href="http://judy.sourceforge.net/">judy</a> - Burst trie (JudyL) by Doug Baskins.
 *  - <a href="http://code.google.com/p/judyarray/">judyarray</a> - Burst trie by Karl Malbrain.
 *  - <a href="http://code.google.com/p/google-sparsehash/">googledensehash</a> - Dynamic open addressing hashtable by Craig Silverstein at Google.
 *  - <a href="http://code.google.com/p/cpp-btree/">googlebtree</a> - Btree by Google.
 *  - <a href="http://panthema.net/2007/stx-btree/">stxbtree</a> - STX Btree by Timo Bingmann.
 *  - <a href="http://www.cplusplus.com/reference/unordered_map/unordered_map/">c++unordered_map</a> - C++ STL unordered_map<> template.
 *  - <a href="http://www.cplusplus.com/reference/map/map/">c++map</a> - C++ STL map<> template.
 *  - <a href="https://sites.google.com/site/binarysearchcube/">tesseract</a> - Binary Search Tesseract by Gregorius van den Hoven.
 *  - <a href="https://code.google.com/p/sparsehash/source/browse/trunk/experimental/libchash.c">googlelibchash</a> - LibCHash by Craig Silverstein at Google.
 *  - <a href="http://concurrencykit.org/">concurrencykit</a> - Non-blocking hash set by Samy Al Bahra.
 *
 * Note that <em>googlelibchash</em> and <em>concurrencykit</em> are not shown in the graphs
 * because they present a lot of spikes. See the \ref notes the end.
 *
 * \section thebenchmark The Benchmark
 *
 * The benchmark consists in storing a set of N pointers to objects and
 * searching them using integer keys.
 *
 * Compared to the case of mapping integers to integers, mapping pointers to objects means that
 * the pointers are also dereferenced, to simulate the object access,
 * resulting in additional cache misses.
 * This gives an advantage to implementations that store information in the objects itself,
 * as the additional cache misses are already implicit.
 *
 * The test done are:
 *  - <b>Insert</b> Insert all the objects starting with an empty container.
 *  - <b>Change</b> Find and remove one object and reinsert it with a different key, repeated for all the objects.
 *  - <b>Hit</b> Find with success all the objects and dereference them.
 *  - <b>Miss</b> Find with failure all the objects.
 *  - <b>Remove</b> Remove all the objects and dereference them.
 *
 * The <i>Change</i>, <i>Hit</i> and <i>Miss</i> tests operate always with N
 * objects in the containers.
 * The <i>Insert</i> test starts with an empty container, and the <i>Remove</i>
 * test ends with an empty container.
 * The objects are always dereferenced, as we are supposing to use them. This
 * happens even in the remove case, as we are supposing to deallocate them.
 *
 * All the objects are preallocated in the heap, and this allocation time is not
 * included in the test.
 *
 * The objects contain an integer <i>value</i> field used for consistency checks,
 * an unused <i>payload</i> field of 16 bytes, and any other data required by the
 * data structure.
 *
 * The objects are identified and stored using integer and unique <i>keys</i>.
 * The key domain used is <strong>dense</strong>, and it's defined by the set
 * of N even numbers starting from 0x80000000 to 0x80000000+2*N.
 *
 * The use of even numbers allows to have missing keys inside the domain for
 * the <i>Change</i> test.
 * In such tests it's used the key domain defined by the set of N odd numbers
 * starting from 0x80000000+1 to 0x80000000+2*N+1.
 * Note that using additional keys at the corners of the domain would have given
 * an unfair advantage to tries and trees as they implicitly keep track of the
 * maximum and minimum key values inserted.
 *
 * The use of the 0x80000000 base, allow to test a key domain not necessarily
 * starting at 0. Using a 0 base would have given an unfair advantage to some
 * implementation handling it as a special case.
 *
 * The tests are repeated using keys in <i>Random</i> mode and in <i>Forward</i> mode.
 * In the forward mode the key values are used in order from the lowest to the highest.
 * In the random mode the key values are used in a completely random order.
 * In the <i>Change</i> test in forward mode, each object is reinserted using the previous
 * key incremented by 1. In random mode each object is reinserted using a completely
 * different and uncorrelated key.
 *
 * The forward order advantages tries and trees as they use the key directly and they have a
 * cache advantage on using consecutive keys.
 * The random order advantages hashtables, as the hash function already randomizes the key.
 * Usually real uses case are in between, and the random one is the worst.
 *
 * \section result Results
 *
 * The most significant tests depend on your data usage model, but if in doubt,
 * you can look at <i>Random Hit</i> and <i>Random Change</i>.
 * They represent the real world worst condition.
 *
 * <img src="def/img_random_hit.png"/>
 *
 * In the <i>Random Hit</i> graph you can see a vertical split at the 100.000 elements limit.
 * Before this limit the cache of modern processor is able to contains most of the data, and it allow a very fast access with almost all data structures.
 * After this limit, the number of cache misses is the dominant factor, and the curve depends mainly on the number of cache-miss
 * required.
 *
 * For rbtree and nedtrie, it's log2(N) as they have two branches on each node, log4(N) for ::tommy_trie_inplace, log8(N) for ::tommy_trie and 1 for hashtables.
 * For ::tommy_trie_inplace and ::tommy_trie you can change the slope configuring a different number of branches for node.
 *
 * <img src="def/img_random_change.png"/>
 *
 * The <i>Random Change</i> graph confirms the vertical split at the 100.000 elements limit.
 * It also show that hashtables are almost unbeatable with a random access.
 *
 * \section random Random order
 * Here you can see the whole <i>Random</i> test results in different platforms.
 *
 * In the <i>Random</i> test, hashtables are almost always winning, seconds are
 * tries, and as last trees.
 *
 * The best choices are ::tommy_hashdyn, ::tommy_hashlin, and googledensehash, with
 * ::tommy_hashlin having the advantage to be real-time friendly and not
 * increasing the heap fragmentation.
 * <table border="0">
 * <tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_insert.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_insert.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_hit.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_hit.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_miss.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_miss.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_change.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_change.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_remove.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_remove.png"/>
 * </td></tr>
 * </table>
 *
 * \section forward Forward order
 * Here you can see the whole <i>Forward</i> test results in different platforms.
 *
 * In the <i>Forward</i> test, tries are the winners. Hashtables are competitive
 * until the cache limit, then they lose against tries. Trees are the slowest.
 *
 * The best choices are ::tommy_trie and ::tommy_trie_inplace, where ::tommy_trie is
 * a bit faster, and ::tommy_trie_inplace doesn't require a custom allocator.
 *
 * Note that also hashtables are faster in forward order than random. This may
 * seem a bit surprising as the hash function randomizes the access even with
 * consecutive keys. This happens because the objects are allocated in consecutive
 * memory, and accessing them in order, improves the cache utilization, even if
 * the hashed key is random.
 *
 * Note that you can make hashtables to reach tries performance tweaking
 * the hash function to put near keys allocated nearby.
 * This is possible if you know in advance the distribution of keys.
 * For example, in the benchmark you could use something like:
 * \code
 * #define hash(v) tommy_inthash32(v & ~0xF) + (v & 0xF)
 * \endcode
 * and make keys that differ only by the lowest bits
 * to have hashes with the same property, resulting in
 * objects stored nearby, and improving cache utilization.
 *
 * <table border="0">
 * <tr><td>
 * <img src="core_i5_650_3G2_linux/img_forward_insert.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_forward_insert.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_forward_hit.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_forward_hit.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_forward_miss.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_forward_miss.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_forward_change.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_forward_change.png"/>
 * </td></tr><tr><td>
 * <img src="core_i5_650_3G2_linux/img_forward_remove.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_forward_remove.png"/>
 * </td></tr>
 * </table>
 *
 * \section size Size
 * Here you can see the memory usage of the different data structures.
 * <table border="0">
 * <tr><td>
 * <img src="core_i5_650_3G2_linux/img_random_size.png"/>
 * </td><td>
 * <img src="core_i7_3740_2G7_win/img_random_size.png"/>
 * </td></tr>
 * </table>
 *
 * \section code Code
 *
 * The compilers used in the benchmark are:
 *  - <b>gcc 4.7.1</b> in Linux with options: -O3 -march=pentium4 -mtune=generic
 *  - <b>Visual C 2012</b> in Windows with options: /Ox /GL /GS-
 *
 * The following is pseudo code of the benchmark used. In this case it's written for the C++ unordered_map.
 *
 * \code
 * #define N 10000000 // Number of elements
 * #define PAYLOAD 16 // Size of the object
 *
 * // Basic object inserted in the colletion
 * struct obj {
 *     unsigned value; // Key used for searching
 *     char payload[PAYLOAD];
 * };
 *
 * // Custom hash function to avoid to use the STL one
 * class custom_hash {
 * public:
 *     unsigned operator()(unsigned key) const { return tommy_inthash_u32(key); }
 * };
 *
 * // Map collection from "unsigned" to "pointer to object"
 * typedef std::unordered_map<unsigned, obj*, custom_hash> bag_t;
 * bag_t bag;
 *
 * // Preallocate objects
 * obj* OBJ = new obj[N];
 *
 * // Keys used for inserting and searching elements
 * unsigned INSERT[N];
 * unsigned SEARCH[N];
 *
 * // Initialize the keys
 * for(i=0;i<N;++i) {
 *     INSERT[i] = 0x80000000 + i * 2;
 *     SEARCH[i] = 0x80000000 + i * 2;
 * }
 *
 * // If random order is required, shuffle the keys with Fisher-Yates
 * // The two key orders are not correlated
 * if (test_random) {
 *     std::random_shuffle(INSERT, INSERT + N);
 *     std::random_shuffle(SEARCH, SEARCH + N);
 * }
 * \endcode
 *
 * \subsection insertion Insert benchmark
 * \code
 * for(i=0;i<N;++i) {
 *     // Setup the element to insert
 *     unsigned key = INSERT[i];
 *     obj* element = &OBJ[i];
 *     element->value = key;
 *
 *     // Insert it
 *     bag[key] = element;
 * }
 * \endcode
 *
 * \subsection change Change benchmark
 * \code
 * for(i=0;i<N;++i) {
 *     // Search the element
 *     unsigned key = SEARCH[i];
 *     bag_t::iterator j = bag.find(key);
 *     if (j == bag.end())
 *         abort();
 *
 *     // Remove it
 *     obj* element = j->second;
 *     bag.erase(j);
 *
 *     // Reinsert the element with a new key
 *     // Use +1 in the key to ensure that the new key is unique
 *     key = INSERT[i] + 1;
 *     element->value = key;
 *     bag[key] = element;
 * }
 * \endcode
 *
 * \subsection hit Hit benchmark
 * \code
 * for(i=0;i<N;++i) {
 *     // Search the element
 *     // Use a different key order than insertion
 *     // Use +1 in the key because we run after the "Change" test
 *     unsigned key = SEARCH[i] + 1;
 *     bag_t::const_iterator j = bag.find(key);
 *     if (j == bag.end())
 *         abort();
 *
 *     // Ensure that it's the correct element.
 *     // This operation is like using the object after finding it,
 *     // and likely involves a cache-miss operation.
 *     obj* element = j->second;
 *     if (element->value != key)
 *         abort();
 * }
 * \endcode
 *
 * \subsection miss Miss benchmark
 * \code
 * for(i=0;i<N;++i) {
 *     // Search the element
 *     // All the keys are now shifted by +1 by the "Change" test, and we'll find nothing
 *     unsigned key = SEARCH[i];
 *     bag_t::const_iterator j = bag.find(key);
 *     if (j != bag.end())
 *         abort();
 * }
 * \endcode
 *
 * \subsection remove Remove benchmark
 * \code
 * for(i=0;i<N;++i) {
 *     // Search the element
 *     // Use +1 in the key because we run after the "Change" test
 *     unsigned key = SEARCH[i] + 1;
 *     bag_t::iterator j = bag.find(key);
 *     if (j == bag.end())
 *         abort();
 *
 *     // Remove it
 *     bag.erase(j);
 *
 *     // Ensure that it's the correct element.
 *     obj* element = j->second;
 *     if (element->value != key)
 *         abort();
 * }
 * \endcode
 *
 * \section others Other benchmarks
 * Here some links to other performance comparison:
 *
 * <a href="http://attractivechaos.wordpress.com/2008/08/28/comparison-of-hash-table-libraries/">Comparison of Hash Table Libraries</a>
 *
 * <a href="http://incise.org/hash-table-benchmarks.html">Hash Table Benchmarks</a>
 *
 * \section notes Notes
 *
 * Here some notes about the data structure tested not part of Tommy.
 *
 * \subsection googlelibchash Google C libchash
 * It's the C implementation located in the <i>experimental/</i> directory of the googlesparsehash archive.
 * It has very bad performances in the <i>Change</i> test for some N values.
 * See this <a href="other/slow_problem.png">graph</a> with a lot of spikes.
 * The C++ version doesn't suffer of this problem.
 *
 * \subsection googledensehash Google C++ densehash
 * It doesn't release memory on deletion.
 * To avoid an unfair advantage in the <i>Remove</i> test, we force a periodic
 * resize calling resize(0) after any deallocation.
 * The resize is executed when the load factor is lower than 20%.
 *
 * \subsection khash khash
 * It doesn't release memory on deletion. This gives an unfair advantage on the <i>Remove</i> test.
 *
 * \subsection nedtrie nedtrie
 * I've found a crash bug when inserting keys with the 0 value.
 * The <a href="https://github.com/ned14/nedtries/commit/21039696f27db4ffac70a82f89dc5d00ae74b332">fix</a> of this issue is now in the nedtries github.
 * We do not use the C++ implementation as it doesn't compile with gcc 4.4.3.
 *
 * \subsection judy Judy
 * Sometimes it has bad performances in some specific platform
 * and for some specific input data size.
 * This makes difficult to predict the performance, as it is usually good until
 * you get one of these cases.
 * See for example this <a href="other/judy_problem.png">graph</a> with a big replicable spike at 50.000 elements.
 *
 * \subsection ck Concurrency Kit
 * It has very bad performances in the <i>Change</i> test for some N values.
 * See this <a href="other/slow_problem.png">graph</a> with a lot of spikes.
 *
 * \page multiindex Tommy Multi Indexing
 *
 * Tommy provides only partial iterator support with the "foreach" functions.
 * If you need real iterators you have to insert all the objects also in a ::tommy_list,
 * and use the list as iterator.
 *
 * This technique allows to keep track of the insertion order with the list,
 * and provide more search possibilities using different data structures for
 * different search keys.
 *
 * See the next example, for a objects inserted in a ::tommy_list, and in
 * two ::tommy_hashdyn using different keys.
 *
 * \code
 * struct object {
 *     // data fields
 *     int value_0;
 *     int value_1;
 *
 *     // for containers
 *     tommy_node list_node; // node for the list
 *     tommy_node hash_node_0; // node for the first hash
 *     tommy_node hash_node_1; // node for the second hash
 * };
 *
 * // search function for value_1
 * int search_1(const void* arg, const void* obj)
 * {
 *     return *(const int*)arg != ((const struct object*)obj)->value_1;
 * }
 *
 * tommy_hashdyn hash_0;
 * tommy_hashdyn hash_1;
 * tommy_list list;
 *
 * // initializes the hash tables and the list
 * tommy_hashdyn_init(&hash_0);
 * tommy_hashdyn_init(&hash_1);
 * tommy_list_init(&list);
 *
 * ...
 *
 * // creates an object and inserts it
 * struct object* obj = malloc(sizeof(struct object));
 * obj->value_0 = ...;
 * obj->value_1 = ...;
 * // inserts in the first hash table
 * tommy_hashdyn_insert(&hash_0, &obj->hash_node_0, obj, tommy_inthash_u32(obj->value_0));
 * // inserts in the second hash table
 * tommy_hashdyn_insert(&hash_1, &obj->hash_node_1, obj, tommy_inthash_u32(obj->value_1));
 * // inserts in the list
 * tommy_list_insert_tail(&list, &obj->list_node, obj);
 *
 * ...
 *
 * // searches an object by value_1 and deletes it
 * int value_to_find = ...;
 * struct object* obj = tommy_hashdyn_search(&hash_1, search_1, &value_to_find, tommy_inthash_u32(value_to_find));
 * if (obj) {
 *     // if found removes all the references
 *     tommy_hashdyn_remove_existing(&hash_0, &obj->hash_node_0);
 *     tommy_hashdyn_remove_existing(&hash_1, &obj->hash_node_1);
 *     tommy_list_remove_existing(&list, &obj->list_node);
 * }
 *
 * ...
 *
 * // complex iterator logic
 * tommy_node* i = tommy_list_head(&list);
 * while (i != 0) {
 *    // get the object
 *    struct object* obj = i->data;
 *    ...
 *    // go to the next element
 *    i = i->next;
 *    ...
 *    // go to the prev element
 *    i = i->prev;
 *    ...
 * }
 *
 * ...
 *
 * // deallocates the objects iterating the list
 * tommy_list_foreach(&list, free);
 *
 * // deallocates the hash tables
 * tommy_hashdyn_done(&hash_0);
 * tommy_hashdyn_done(&hash_1);
 * \endcode
 *
 * \page design Tommy Design
 *
 * Tommy is mainly designed to provide high performance, but much care was
 * also given in the definition of an useable API. In case, even making some
 * compromise with efficency.
 *
 * \section multi Multi key
 * All the Tommy containers support the insertion of multiple elements with
 * the same key.
 *
 * This allow the maximum flexibility, but in some cases it requires some
 * more space to keep a list of equal elements.
 *
 * \section datapointer Data pointer
 * The tommy_node::data field is present to provide a simpler API.
 *
 * A more memory conservative approach is to do not store this pointer, and
 * computing it from the embedded node pointer every time.
 *
 * See for example the Linux Kernel declaration of container_of() at
 * http://lxr.free-electrons.com/ident?i=container_of
 *
 * Although, it would have required more complexity for the user to require
 * a manual conversion from a node to the object containing the node.
 *
 * \section zero_list Zero terminated next list
 * The half 0 terminated format of tommy_node::next is present to provide
 * a forward iterator terminating in 0.
 *
 * A more efficient approach is to use a double circular list, as operating on
 * nodes in a circular list doesn't requires to manage the special terminating
 * case.
 *
 * Although, it would have required more complexity at the user for a simple
 * iteration.
 *
 * \section double_linked Double linked list for collisions
 * The linked list used for collision is a double linked list to allow
 * insertion of elements at the end of the list to keep the insertion order
 * of equal elements.
 *
 * A more memory conservative approach is to use a single linked list,
 * inserting elements only at the start of the list.
 * On the other hand, with with a double linked list we can concatenate
 * two lists in constant time, as using the previous circular element we
 * can get a tail pointer.
 *
 * \page license Tommy License
 * Tommy is released with a <i>2-clause BSD license</i>.
 *
 * \code
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * \endcode
 */

/** \file
 * All in one include for Tommy.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "tommytypes.h"
#include "tommyhash.h"
#include "tommyalloc.h"
#include "tommyarray.h"
#include "tommyarrayof.h"
#include "tommyarrayblk.h"
#include "tommyarrayblkof.h"
#include "tommylist.h"
#include "tommytrie.h"
#include "tommytrieinp.h"
#include "tommyhashtbl.h"
#include "tommyhashdyn.h"
#include "tommyhashlin.h"

#ifdef __cplusplus
}
#endif

