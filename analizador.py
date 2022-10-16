#!/usr/bin/env python3

import argparse
from scapy.all import *


''' Clase que encapsula el análisis de las tramas 
   para seleccionar la interfaz adecuada a través
   de la cual se recibe el tráfico de red '''
class Analizador:


    def __init__(self, args):
        self.args = args

    def __call__(self, packet):
        print('Paquete:',packet.summary(), sep='\n')
        packet.show()

    def run_forever(self):
        sniff(iface=self.args.interface, prn=self, store=0)


if __name__ == "__main__":
    ''' El nombre de la interfaz se recibe por medio del
        argumento -i en la línea de comandos'''
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, required=True, help='Nombre de la interfaz')
    args = parser.parse_args()
    analizador = Analizador(args)
    analizador.run_forever()