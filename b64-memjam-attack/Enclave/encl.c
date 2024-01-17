#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <tsgxsslio.h>

#include "encl_t.h"

#include "mem_read.h"


char *private_key_data = "-----BEGIN RSA PRIVATE KEY-----\n"
                         "MIIG4gIBAAKCAYEAu17bWllqiRJPWi0FQEqh7lHZJL7A9WfzVem417MRKUakbPEZ\n"
                         "29Po5KcUfE+w2Q6V3fBr+I2DtVws7Y8Q8Lzj0w/COrW7OO7iu1uvS8SJo7SjsFSH\n"
                         "N0RfM477TYZ+EXWB6bcSQvDoQo0Y5MJyKOEb7ycrHu6DEug3tPlVoyzm0wjLPF5G\n"
                         "2pVjHHPelDAnX5WHioEsZkepAALMGMLzSCV9E/iCx0dU7BiDcTeJp/kXTho+y0nm\n"
                         "5eB9j4dE2Y2w3Xag4cfSwrwM0T6b38shYYKeSuGdGVgltQFTDy8vNFJ91HHtRiBF\n"
                         "g3yoOSdl6x8zUmVUgN+lbLbBX02imLJfGkBMkIA5OKmLg2hqjZMsgL3XedPwac7i\n"
                         "jYbDNwJQml8J+uxd21UZMH+NORQi3pfUaUZcNAtzJCXLY4NwZMfKSV6CHXnYh/Eh\n"
                         "zrUinuTNgC/xpnS6jOQmghZMGLMCI37AXfOdkwCPg1JABwMMQbQaz7Ngi4vV0ijE\n"
                         "0V42QgU+cTm+VxkFAgEDAoIBgHzp55GQ8bC235FzWNWHFp7hO23UgKOaojlGezp3\n"
                         "YMYvGEigu+fim0MaDag1IJC0Y+lK8qWzrSOSyJ5fYKB97Tdf1tHOfNCfQdI9H4fY\n"
                         "W8J4bSA4WiTYP3e0p4kEVAujq/EkttdLRYGzZe3W9sXrZ/TEx2n0V2HwJSNQ48Id\n"
                         "7zdbMig+2ecOQhL36bggGj+5BQcAyEQvxgAB3WXXTNrDqLf7AdovjfK7Akt6W8VQ\n"
                         "ujQRfzIxRJlAU7UE2JEJIJOkahyF7xL86k+a2wMLQ/jYmtNMsJC/cUE4KZB7LitR\n"
                         "qzKknhsikYwTNB8apT+e0cOTiflC41K/mqhTlPsXF7EY2jNmTieTVb+ktuJ0XgIR\n"
                         "1iaiwWHf1oqxXlfGlimfKnL9Yc02ziav/tuldEjzKPwppU0gk6XZX05rCTe9Iiho\n"
                         "uKsXbjg+DKlQIj4CJQR6Wx1yW3lRmHtD1H1jn05C2RpPrveWpxEI+7Fe6dm8qv1j\n"
                         "JNZ4/+WVHxTMzUI2ceAS+fsdcwKBwQDqEwAbmPl8emPLrJrLktC/sGhTzcl2UnQu\n"
                         "egnoWMr2yeLRc/rT4JhanftUyQsP5Y2ZtU0CkNzo0rpzlzUZTCKS2a+FesK5oxk1\n"
                         "qWonRGOkXIRAwey+vfAcAHhQ8VjGWiiRy3SyBi44ECpJQ4pHSgWxO6PiuLX3H5mK\n"
                         "uy1xH0WjPsXOetz3x/1ThL//8vJIgi3lXYVcsKxU0Fo6WVR8SfnlUzP4GRrkcMJi\n"
                         "NwUZ7CHeBnaoSXmPubm/esWZTKis4yMCgcEAzOvsCqez3Vvvj42goKrlTj4r7Gsy\n"
                         "XNqgh/xgCv8yEbEdS/hwXX9Br+FytuftnSJ38UYDbgZ8ef2IrHiGd07isI0Ud9HI\n"
                         "Kk4/BDs1Vl6ym4NKFj0z/r7Fl1f3Cv7xiBYilbdvRHFgt4vKJ+eMp73ejx7xyKcG\n"
                         "dsNJBnDpm6IneZftZRkx2PTx7lzV+YV2sccDcYw8bH/hB80488EmOjIdOktg8aur\n"
                         "mIPrGOIVObKHa8/fUX+conFInzjOB9CesYm3AoHBAJwMqr0QplL8QofIZzJh4H/K\n"
                         "8Dfehk7hosmmsUWQh08xQeD3/I1AZZG+p43bXLVDs7vOM1cLPfCMfE0PeLuIFwyR\n"
                         "H65R1yZsu3kbnBotl8LoWCsr8ynT9WgAUDX2Oy7mxbaHoyFZdCVgHDDXsYTcA8t9\n"
                         "F+x7I/oVEQcnc6C/g8Ip2TRR6KUv/jet1VVMoYWsHpjpA5MgcuM1kXw7jagxUUOM\n"
                         "zVAQvJhLLEF6A2ada+lZpHAw+7Ume9T8g7uIcHNCFwKBwQCInUgHGnfo5/UKXmsV\n"
                         "x0OJfsfy8iGTPGsFUuqx/3a2dhOH+vWTqivKlkx57/O+Fvqg2Veerv2mqQXIUFmk\n"
                         "30HLCLhP4TAcNCoC0iOO6cxnrNwO03f/KdkPj/oHVKEFZBcOekotoOslB9waml3F\n"
                         "KT8KFKEwb1mkgjCu9fESbBpRD/OYu3aQo0v0PeP7rk8hL1ehCChIVUCv3iX31hl8\n"
                         "IWjRh5X2cnJlrUdl7A4mdwTyipTg/73BoNsU0IlaixR2W88CgcBoZbCZiGEMHUFi\n"
                         "S/bej+Z6Jzh0MBV1+OfSpRv5F9kNLRqOnIqlVdveYIaL81xcBVLEAQG0EIhIFi+H\n"
                         "C16xeGGpjeqU/Xu7KxGoSB0WDWQY1udBgT1RN+Z7ajMFzuJFdCGfg8TyUX4AN5/U\n"
                         "0NwxA/IhIDI4OjnV+1UazgLb30znaazFFsLLybq/vYcOhLglaYBDeE0834Wu94i3\n"
                         "kauq6Wcnh7qkISmMDMsMirVlVbcOHUwqnW6FagGwsV4/ljuU8ug=\n"
                         "-----END RSA PRIVATE KEY-----";

char *private_key_data_1024 = "-----BEGIN PRIVATE KEY-----\n"
                              "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMUwt5PUgUIj6/F3\n"
                              "3WuawCxFBeZEIBxeix2mPfR3x94qzFmvFPVrnXBI8aRAhY+CuWx6jPJ/jnQvQcsy\n"
                              "HHyFFE6h9xe31R86WUMh2uq1Ny7wGU2wRIr6YlHjKAh5gDLzCL3XGzv72dv0clbO\n"
                              "TUZHVGGFd5OX0KRk/Am0w+j8JKkzAgMBAAECgYB2Jq6YYSfh3WwuDsgZBWxIGkNi\n"
                              "qUckOHHanhVZObwEHli7E/DW7Fg1Qz+mTxK33ngDy5pQYqWUcAxYF/qBkauMM9xN\n"
                              "gwdc6JCjyztM6g0j81QHduQs+QPnRIYZDoPIc5HX0EVcwTjfH2tmQMvB7THFQuDe\n"
                              "rIMgLh/pRDd59hd5oQJBAPNdo3SJxnlvfMxjWq6naJnp1n9+E7lvo5qNNjpSnKCs\n"
                              "zo8vwpvML6hNiG0FFRKnyg8AM8QE09U/rvsw66Iz6B8CQQDPbWaaTutwOF5+x30B\n"
                              "q/os07vb3sVLh5RwNQgXnQxF7nDEP5ECqQnwVeYOjU4egrIVV0NeOnSu7GstxPcp\n"
                              "KqxtAkArlofiJZMQyPEXQmxJf95yQrmSWCh8PAyXb9dYltdKx+ivKKS4dtfKUyiu\n"
                              "LgzaLIc6LJUY9KxkM2XJw7dQc++NAkEAwG5u1FLIyugQii8JgoaIZhPb4ONvR121\n"
                              "UM9x/W4d17aX+Qg7wCsP5F3cOr3OrjFzgqbdAcrbOvhrih+DaDaFlQJBAIkoJMeT\n"
                              "MM8p8PJki3Yfsetvg/WewB71UOAdr0sJRi7w6hPjMFOgc+JJg78S/0NbFu49Hgkm\n"
                              "obNOGJpUhF3CjBk=\n"
                              "-----END PRIVATE KEY-----";


char *private_ossl_euler_key_4096bit = "-----BEGIN PRIVATE KEY-----\n"
                              "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCaCHDAaFAwgPUZ\n"
                              "qDjHE3iA2dkVYTyS0FtlWgUqhrQFpGOHATQcskr07+Q85yyzy5LQyn8C7zKr66y0\n"
                              "HfO5DdzUfqe6bz9FvR2u+ek41jZStzJ/gV3ifHf4sVN75D0shEqDAz3S+rNtqdwR\n"
                              "qMt86eBNLuGGnGHR9GJZ8VYHjwgbxh2GbTWglpHaMUp1enp8cBezsquOcj7Jr9Sl\n"
                              "mPSbcamL45n1VRezOeA3CyhZCUfPqn02YabqF7z7atmSd0bJZTpJ2LlFqPdGS24o\n"
                              "/cgNDmMUxhvfVjQRoQUDntW0+n9yUf3nWXUO5L2ph+1SitojKTkIHC+Ece+eViRw\n"
                              "tixufo+DFR8UyQy0gcu6GeVFaovgo/JLKRrD3DVJC9hjohFQM12JQ3yZuonMJjbU\n"
                              "rkEW66MegN1yJoXQB09BUKYjei603YK91eQ0/XglwlDRMpxasbTQUglST1EJqhOd\n"
                              "v3GlzZq0pKj3tamgRyrGGQG27BfKx9/hU+Se0Cfg0rcJATrDk6EQQp3+3XP4uP3P\n"
                              "4uotZznvkYYvp+ApLJf7RE9X8EVt/lyln751SyuDREl3kdWkDq3UZchpdraL/Pm/\n"
                              "87f4RmCyBHR6ziBAmVar26bfLkWfTU+C2PP+pSlAy4Wp1+our9zuQkFzrxxCQAob\n"
                              "PJNVvgWEnNEO7Bje6y6BynHBt2Y4kwIDAQABAoICAAJrIYIT4TZxv+dwObv+dUTo\n"
                              "przsMuxHMzgrKquZQ9hW1W04Op48umqQHbBLHOuRxbNbipT8Nnp2j9agJcSBEDeR\n"
                              "6YZG2uJ4bq/hoqTO0DmKQNO5r0SwGZ4hAqOOWNuLFDRsZ5sZbpnJMfhhAxjp/yiX\n"
                              "FNltOSf3w1eQL36c4060VKBYtJ/Z3V5kqbugea3cgLLEmmb5Kj02cotLFIQgS74z\n"
                              "i6ZLeLzKqteSaEbFm4gKMD8bV2iTiNcVvWbMUqM04K5qJbaPSZqj8o3YNjzmPe4E\n"
                              "kkl2bAje01pUMxzNVhTwbqEkSW87bjLsPHCwV2535jpXXvOgale9GINgiOAPQqeQ\n"
                              "/3QUevBKTDb8RmVIYPxtolKEZGR2r2KqLQGPcY0m/XtgA1w4yBE4shP/Vb5n+JKO\n"
                              "2p7MRd1AJllUJFCa7lyHvW8F38UKhThkgwkHpjyNRtIgcGsIsvB4AddV/qDcKV9R\n"
                              "xus9cIA8THyJ0n7WxKZu+L9E5gTKFBZauWfE6ZAorLbXrCdfKrcsUzOzF3uqJIdG\n"
                              "j3CK/eO47D3Ed63IW+dLVERcK0XNWGQIC3zgxxm4GUwiTg53K6Eo5C4QS97hw8lp\n"
                              "8srwYW2Y/XgLPq7nfBOKig6qBK7G7bO4fBdDj5ziOtjDq0lBGzaevGYZrqujNyBW\n"
                              "cykRH65sn64zXYwOMxMhAoIBAQDLrO8pqC5SRpcl+lcNIHAolwR1oh+FI0VArBRc\n"
                              "DsiljC9AMlg4Cd8fXhhS8rFpUn4Ierbj0Ov/xYD3O5nmzympWR/xdVIDp+NIF0tw\n"
                              "9RgO3s5LAULd5Ac9rY9C/PLt0JfMRaLLxOh2Ye+BLeiAHDBx9Ixh2onQ9S7w+k2P\n"
                              "uzWERX5dpaaAke+M+DCohoYSHtHut+nRXs1yTRCwgQW2ZXj1yv00ul9MwvagPfQa\n"
                              "n73+wRf/j1/XlotXdKt6/FbRduGYdnnD7W7HnvT7iTCiK0y3kIl1AQ4gF8J4JO6E\n"
                              "gboRj5aob4mT90auqgvW6jIVo5bp1AUcZtKUF9mlG31qMsijAoIBAQDBmq35MxKw\n"
                              "w0MsTBFAPrS+V4G789OXC7VJY5sKhb1n2DoLkNo6h2OB67hF+aALZqMZzYwEmCZz\n"
                              "nEqNQI49zKVNDNEQxL0Wm4nyCGCEYstXHM+1S10I8VJL+r6qvSGix4FRPQO4cxqi\n"
                              "FQHODduKteSRVYDR392+DAaEAUYvvH1VDJOKKhdZoIVOQtEpLXqk6v8DZ79i9hwV\n"
                              "2sqOeG2VQdDm1+SD/GF4g5LAhq5wf6oOLdwYDo1r2gMBPLHVi9HPzWh+2TY8nE9a\n"
                              "CQ8EQfel+zfP0Bb6IQQFkjPkd28JDUodf5km3l9vXcYXdzznlWfacnWkL6l18ljj\n"
                              "3/e+5nUgYx9RAoIBAQCxKB5usWZ5EgVudy04sbpc096BIx8fguo9sm+TExjbRe/j\n"
                              "eubY910nv4SQwaAm6CXP4k0qIxLjSjs+0IyxAghO0MLEFzPbEjDTB9AK1GS0qn/t\n"
                              "JY+vySOzNj+iGLqEuCcQ+pD7hK5eKhlU10WgCOTqebeRdbDiHCFUYaMNHd0SzA96\n"
                              "DReiRU2D5G0OaNQ89qnLZhTuk/NHNFkL7W22lNR9lq5fKqyx6/LwtnKYpdFwwSvK\n"
                              "kj7fGobg7w4oz0wErc7T+lk3XlI5N74G+/FdXSRBlmq5Zs2OhJwWPKlqgBwEIkz8\n"
                              "/OdB2JeWXTonGVWvFLezc0NuzNDlF0msHxkbQkjZAoIBAD8NgVuHpq6q6VWj8Hpb\n"
                              "8cGL/lSYNHEc/w3HwtbKd8U6Rq09n9UwAthtTLZ9dgJAix38M33Lj7pXTHB0dd7q\n"
                              "p2tQoUY0zOBwB50r3UNAabkVSRBiWwpujb7xCufQcQPytcsfc/a+hg4DiXLyUG38\n"
                              "j1RF5I51umIKyJR1VcZ2PNtWHTcCPliSTtgOKtCeXzMW1bbmMw6n2L3FY/LChe32\n"
                              "YXLNHT9fEt+M+l55fpZk/Z1gki3Dj4twlUnx2nkR8GMdIsstMtzKi41nJdzdHyqP\n"
                              "hr3Hp7QOzKCD3SKrQx5PlbPFurtN8Qb0I2/BBbTmk8wxOt8eJrKjGxAcATPLGppR\n"
                              "rgECggEARK5FSE7/QAZUPcIgDo2oMiFnO892DOCKSbkeZ9y0tDqfrGbjo8sfuFls\n"
                              "OsWts2MW33D+fNX2K8zfF36DlEHZuhjpsKhhdh6VB47FRMZctpV9q4zJrMy5gsnR\n"
                              "Oda9Ixacg7Lf/WjmPNOg0YY7fmhexNY355lYyRkkjb/ZtzJLatamlSqIpJwxaEz6\n"
                              "xhfRMG2x8Rgcz9HB0MgQ2MuE86LzWToI49v2y9deLugHHdn2TKG4hRA1JDHfZU7g\n"
                              "uGsDFEgIzonc2g7X4qqnSHqI+lnS6rgSJb0vjoe3NZd6Op+CQtwl/2xZe5KG+KdY\n"
                              "gL+vG+Wkeg1BNjb3eNIpAjmzOVSABQ==\n"
                              "-----END PRIVATE KEY-----";


void rsa_key_load(void) {
  RSA *key;
  BIO *key_bio;

  key_bio = BIO_new_mem_buf(private_ossl_euler_key_4096bit, -1);
  key = PEM_read_bio_RSAPrivateKey(key_bio, NULL, NULL, NULL);
  BIO_free(key_bio);
  RSA_free(key);
}

void* get_rsa_key_load_addr(void) {
  return rsa_key_load;
}
