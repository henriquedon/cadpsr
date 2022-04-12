# CadPSR
# Projeto Integrador 1 - Univesp 2021

**ROTEIRO PARA EXECUÇÃO DA APLICAÇÃO DESENVOLVIDA**

Recomendo utilizar um ambiente virtual para testar aplicação.

Com o Python 3.8 ou 3.9 (só testei nessas versões) e com o venv (ou outro) devidamente ativado, execute o comando:

>> git clone https://github.com/henriquedon/cadpsr

Em seguida instale o Flask e as dependências do projeto a partir do arquivo requirements.txt

>> pip install -r requirements.txt

O arquivo '.flaskenv' contém os comandos referentes às variáveis de ambientes a fim de facilitar a execução do CadPSR. Caso você utilize Windows,
verifique quais comandos são necessários.

Agora é necessário efetuar a primeira migração do App. Utilize os comandos em sequência:

>> flask db init

>> flask db migrate

>> flask db upgrade

Será necessário criar a conta do Gestor do CadPSR. Criei um script em Python para facilitar as coisas. Execute:

>> python3 geracao_dados.py

Será pedido uma senha. O e-mail do Gestor será informado, é através dele que se faz o acesso ao o sistema.

Ainda no terminal, execute o comando:

>> flask run

Copie o endereço em que o servidor local está sendo executado e utilize um navegador web de sua escolha.

Informe o e-mail e a senha.


