#include <iostream>
using namespace std;

class object
{
private:
    int data;
public:
    object(int d = 0):
        data(d)
    {
        cout << "default constructor" << endl;
    }
    
    object(const object& other):
        data(other.data)
    {
        cout << "copy constructor" <<endl;
    }
    
    object& operator=(const object& other)
    {
        if(&other != this)
        {
            data = other.data;
            cout << "assignment constructor" <<endl;
        }
        return *this;
    }
};

void behavior1(object other)
{
    cout << "test behavior1" << endl;
}

void behavior2(object& other)
{
    cout << "test behavior2" << endl;
}
int main()
{
    object A;
    cout << endl;
    object B(A);
    cout << endl;
    object C = A;
    cout << endl;
    C=B;
    cout << endl;
    behavior1(A);
    cout << endl;
    behavior2(A);
    return 0;
}