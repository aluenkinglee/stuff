#include <iostream>
#include <vector>

#include <string.h>
#include "stl_func"
#include "base_iterator"
#include "base_alloc"
#include "hashtable"
#include "hash_set"


int main()
{
    typedef __hashtable_nodes<int> node;
    typedef hashtable<int,int,hash<int>,identity<int>,equal_to<int>,std::allocator<node> > Ihashtable;
    typedef Ihashtable::iterator Iiterator;

    Ihashtable iht(50, hash<int>(), equal_to<int>());

    std::cout << iht.size() << std::endl;
    std::cout << iht.bucket_count() << std::endl;
    std::cout << iht.max_bucket_count() << std::endl;

    iht.insert_unique(59);
    iht.insert_unique(63);
    iht.insert_unique(108);
    iht.insert_unique(2);
    iht.insert_unique(53);
    iht.insert_unique(55);
    std::cout << iht.size() << std::endl;

    Iiterator ite = iht.begin();
    for (unsigned int i = 0;
            i < iht.size();
            ++i,++ite)
        std::cout << *ite << ' ' ;
    std::cout << std::endl;

    for (size_t i =0 ;i<iht.bucket_count();++i) {
        size_t n = iht.elems_in_bucket(i);
        if(n!=0)
            std::cout<<"bucket[" << i << "] has "<<n<<"elems." <<std::endl;
    }

    for(size_t i = 0; i<=47;i++)
        iht.insert_equal(i);
    std::cout << iht.size() << std::endl;
    std::cout << iht.bucket_count() << std::endl;

    for (size_t i =0 ;i<iht.bucket_count();++i) {
        size_t n = iht.elems_in_bucket(i);
        if(n!=0)
            std::cout<<"bucket[" << i << "] has "<<n<<"elems." <<std::endl;
    }

    ite = iht.begin();
    for (unsigned int i = 0;
            i < iht.size();
            ++i,++ite)
        std::cout << *ite << ' ' ;
    std::cout << std::endl;

    std::cout<<*(iht.find(2)) << std::endl;
    std::cout<<iht.count(2) << std::endl;

    hash_set<const char*, hash<const char*>, eqstr> set;
    set.insert("kimi");
    std::cout << *set.find("kimi");
    return 0;
}

//passing 'const ht {aka const hashtable<char*, char*, hash<char*>, identity<char*>, eqstr, std::allocator<char*> >}' as 'this' argument of 'hashtable<Value, Key, HashFcn, ExtractKey, EqualKey, Alloc>::iterator hashtable<Value, Key, HashFcn, ExtractKey, EqualKey, Alloc>::find(const Key&) [with Value = char*; Key = char*; HashFcn = hash<char*>; ExtractKey = identity<char*>; EqualKey = eqstr; Alloc = std::allocator<char*>; hashtable<Value, Key, HashFcn, ExtractKey, EqualKey, Alloc>::iterator = __hashtab|
