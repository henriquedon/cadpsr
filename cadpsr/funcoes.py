

def carimbo_data(data):
    data = data.split('-')
    hora, minuto, segundo = data[3], data[4], data[5]
    dia, mes, ano = int(data[0]), data[1], data[2]
    meses = {'01': 'jan.', '02':'fev.', '03':'mar.', '04':'abr.', '05':'maio',
             '06':'jun.', '07':'jul.', '08':'ago.', '09':'set.', '10':'out.',
             '11':'nov.', '12':'dez.'}
    mes = meses[mes]
    carimbo_data = f'{dia} {mes} {ano}, {hora}h{minuto}m{segundo}'
    return carimbo_data

def lista_para_str(lista):
    string = ''
    for i in lista:
        string += str(i)
    return string
