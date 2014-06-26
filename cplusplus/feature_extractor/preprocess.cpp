#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <vector>

#define tuple_SIZE 5
#define timeintervals_SIZE 9
#define lens_SIZE   10
#define features_SIZE 10

#define DEBUG 1


using namespace std;
class Preprocess
{
private:
    fstream in;
    fstream out;
    vector<string> tuple;
    vector<double> timeintervals;
    vector<int> lens;
    vector<int> features;

public:
    Preprocess()
    {
        in.open("features.txt", ios::in);
        //重新建立文件 原来的销毁。
        out.open("features.arff", ios::out);
        tuple.resize(tuple_SIZE);
        timeintervals.resize(timeintervals_SIZE);
        lens.resize(lens_SIZE);
        features.resize(features_SIZE);
    }
    ~Preprocess()
    {
        in.close();
        out.close();
    }
private:
    void split(const string& src, const string& delim, vector<string>& dest)
    {
        string str = src;
        string::size_type start = 0, index;
        string substr;

        index = str.find_first_of(delim, start);
        while(index != string::npos)
        {
            substr = str.substr(start, index-start);
            dest.push_back(substr);
            start = str.find_first_not_of(delim, index);
            if(start == string::npos) return;
            index = str.find_first_of(delim, start);
        }
        substr = str.substr(start);
        dest.push_back(substr);
    }

    template <class T>
    void convertFromString(T &dest, string &source)
    {
        stringstream ss(source);
        ss >> dest;
    }

    void ipstrToNum(string &ip)
    {
        vector<string> tmp;
        split(ip, ".", tmp);
        long sum =0,value;
        char buf[50];
        for(int i =0; i<tmp.size(); i++)
        {
            convertFromString(value,tmp[i]);
            sum += value*(2<<(3-i))*256;
        }
        sprintf(buf,"%ld",sum);
        string new_form(buf);
        ip =  new_form;
    }

    template <class T>
    void display(vector<T> data)
    {
        typename vector<T>::iterator iter;
        for(iter = data.begin(); iter!=data.end(); ++iter)
            cout << *iter << " " ;
    }

    void arffHead()
    {
        out<<"@relation processed\n\
\n\
@attribute sip numeric\n\
@attribute sport numeric\n\
@attribute dip numeric\n\
@attribute dport numeric\n\
@attribute protocal numeric\n\
@attribute interval1 numeric\n\
@attribute interval2 numeric\n\
@attribute interval3 numeric\n\
@attribute interval4 numeric\n\
@attribute interval5 numeric\n\
@attribute interval6 numeric\n\
@attribute interval7 numeric\n\
@attribute interval8 numeric\n\
@attribute interval9 numeric\n\
@attribute packet_len1 numeric\n\
@attribute packet_len2 numeric\n\
@attribute packet_len3 numeric\n\
@attribute packet_len4 numeric\n\
@attribute packet_len5 numeric\n\
@attribute packet_len6 numeric\n\
@attribute packet_len7 numeric\n\
@attribute packet_len8 numeric\n\
@attribute packet_len9 numeric\n\
@attribute packet_len10 numeric\n\
@attribute payload_len1 numeric\n\
@attribute payload_len2 numeric\n\
@attribute payload_len3 numeric\n\
@attribute payload_len4 numeric\n\
@attribute payload_len5 numeric\n\
@attribute payload_len6 numeric\n\
@attribute payload_len7 numeric\n\
@attribute payload_len8 numeric\n\
@attribute payload_len9 numeric\n\
@attribute payload_len10 numeric\n\
\n\
@data"<<endl;
    }

public:
    /// ip从字符串格式变为数字。
    void process()
    {
        vector<string> tmp;
        arffHead();
        while(!in.eof())
        {
            tmp.clear();
            for(int i= 0; i<tuple_SIZE; ++i )
            {
                in >> tuple[i];
                if(i==0 || i==2)
                {
                    tmp.clear();
                    ipstrToNum(tuple[i]);
                }
#ifdef DEBUG
                cout << tuple[i] << ",";
#endif
                out << tuple[i] << ",";
            }
            for(int i= 0; i<timeintervals_SIZE; ++i )
            {
                in >> timeintervals[i];
#ifdef DEBUG
                cout << timeintervals[i] << ",";
#endif
                out << timeintervals[i] << ",";
            }
            for(int i= 0; i<lens_SIZE; ++i )
            {
                in >> lens[i];
#ifdef DEBUG
                cout << lens[i] << ",";
#endif
                out << lens[i] << ",";
            }
            for(int i= 0; i<features_SIZE-1; ++i )
            {
                in >> features[i];
#ifdef DEBUG
                cout << features[i] << "," ;
#endif
                out << features[i] << ",";
            }
            in >> features[features_SIZE-1];
#ifdef DEBUG
            cout << features[features_SIZE-1] ;
            cout << endl;
#endif
            out << features[features_SIZE-1] ;
            out << endl;
        }
    }


};

template <class T>
void convertFromString(T &dest, string &source)
{
    stringstream ss(source);
    ss >> dest;
}

template <class T>
string convertToString(T value)
{
    std::stringstream ss;
    ss << value;
    return ss.str();
}

int main()
{
    Preprocess p;
    p.process();
    return 0;
}
