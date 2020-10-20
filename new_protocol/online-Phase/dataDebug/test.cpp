
#include <iostream>
#include <gmp.h>

int main(int argc, char *argv[])
{
	mpz_t modular;
    mpz_init(modular);
    mpz_set_ui(modular,1);
    mpz_mul_2exp(modular,modular,128);


	char * line = NULL;
    size_t len = 0;
    ssize_t read;
	FILE *pDebug1 = fopen("../debugAlice.txt","r");

	FILE *pDebug2 = fopen("../debugBob.txt","r");
	while(1){

		getline(&line, &len, pDebug1);
		if(line ==NULL){
			break;
		}
		else{
			//analyse line
			std::string str1(line);
			mpz_t r1;
			mpz_init(r1);
			mpz_set_str(r1,str1.c_str(),16);


			getline(&line, &len, pDebug2);
			std::string str2(line);
			mpz_t r2;
			mpz_init(r2);
			mpz_set_str(r2,str2.c_str(),16);
			mpz_sub(r2,modular,r2);



			mpz_add(r1,r1,r2);
			mpz_mod(r1,r1,modular);

			mpz_div_2exp(r1,r1,120);

			uint32_t high = mpz_get_ui(r1);

			if(high !=0){
				std::cout<< str1 <<std::endl;
				std::cout<< str2 <<std::endl;
				std::cout<<std::endl<<std::endl;
			}
		}
	}
	
    fclose(pDebug1);
    fclose(pDebug2);
}