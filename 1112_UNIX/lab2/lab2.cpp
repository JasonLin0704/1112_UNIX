#include <iostream>
#include <dirent.h>
#include <fstream>
#include <string>
#include <string.h>
#include <unistd.h>
#include <limits.h>

using namespace std;

void dfs(string path, string magic){
    DIR *dir; 
    struct dirent *dirp;

    if(!(dir = opendir(path.c_str()))){
        cerr<<"Cannot open a directory!"<<endl;
        return;
    }

    while((dirp = readdir(dir)) != NULL){
        string file_name(dirp->d_name);
        string file_path = path + "/" + file_name; cerr<<file_path<<endl;

        if(file_name == "." || file_name == "..") continue;

        switch(dirp->d_type){
            case DT_DIR:
                cerr<<"dir "<<file_path<<endl;
                dfs(file_path.c_str(), magic);
                break;
            case DT_LNK:
                cerr<<"symbolic link "<<file_path<<endl;
                break;
            case DT_REG:{
                cerr<<"file "<<file_path<<endl;
                cerr.flush();
                ifstream fin;
                fin.open(file_path);
                if(!fin.is_open()){
                    cerr<<"Cannot open a file! "<<file_path<<endl;
                    continue;
                }
                string str;
                while(fin>>str){
                    if(str.find(magic) == string::npos) continue;
                    else{
                        cerr<<"find!"<<endl;
                        cout<<file_path;
                        cerr<<endl;
                        exit(0);
                    }
                }
                fin.close();
                break;
            }
            default:
                break;
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]){
    
    string path(argv[1]), magic(argv[2]);

    cerr<<"path: "<<path<<endl;
    cerr<<"magic: "<<magic<<endl<<endl;

    dfs(path, magic);
    
    return 0;
}