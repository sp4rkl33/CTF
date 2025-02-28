#include <bits/stdc++.h>

using namespace std;

int main(){
    freopen("rev_this", "r", stdin);
    char c[24]; for (auto &it:c) cin >> it;
    for (int i = 8; i <= 22; i++){
        if (i & 1) c[i] += 2;
        else c[i] -= 5;
    }

    for (int i = 0; i < 24; i++) cout << c[i];
    cout << '\n';
    return 0;
}
