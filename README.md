# cadpsr
# Projeto Integrador 1 - Univesp 2021

ROTEIRO PARA EXECUÇÃO DA APLICAÇÃO DESENVOLVIDA

Recomendo utilizar um ambiente virtual para testar aplicação.

Com o Python 3.8 ou 3.9 (só testei nessas versões) e com o venv (outro) devidamente ativado, execute o comando:

git clone https://github.com/henriquedon/cadpsr

Em seguida instale o Flask e as dependências do projeto a partir do arquivo requirements.txt

pip install -r requirements.txt

O arquivo .flaskenv contém os comandos referentes às variáveis de ambientes a fim facilitar a execução do CadPSR. Caso você utilize Windows,
verifique os comandos corretos a serem informado no referido arquivo.

Agora é necessário efetuar a primeira migração do App. Utilize os comandos em sequência:

>> flask db init
>> flask db migrate
>> flask db upgrade

Será necessário criar a conta do Gestor do CadPSR. Criei um script em python para facilitar as coisas. Execute:

>> python geracao_dados.py

Será pedido uma senha.
Se tudo ocorrer bem, você será informado com o login de acesso ao sistema.

Ainda no terminal, execute o comando:

>> flask run

Copio o endereço em que o servidor local e execute no navegador de sua escolha.

Informe o e-mail e a senha.

