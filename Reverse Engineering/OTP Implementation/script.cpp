#include <bits/stdc++.h>

using namespace std;

int jumble(char a){
    int x, y;
    x = a;
    if (a > 96) x += 9;
    y = 2 * (x & 15);
    if (y > 15) ++y;
    return y;
}

char c[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

int main(){
    string enc = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe", key(100, '0');
    
    //fine the first char
    for (auto it:c)
        if ((char)(jumble(it)) % 16 + 97 == 'b') {
            key[0] = char(jumble(it));
            cout << it; //print each char
            break;
        }

    //fine the rest key;
    for (int i = 1; i < 100; i++){
        for (auto it:c){
            int v4 = jumble(it), v5 = key[i - 1] + v4;
            if ((v5 & 15) + 97 == (int)enc[i]) {
                key[i] = v5 & 15;
                cout << it; //print each char
            }
        }
    }

    return 0;
}
