import org.car2x.veins.subprojects.veins_inet.VeinsInetCar;
import inet.applications.contract.IApp;

module VanetAodvCar extends VeinsInetCar
{
    submodules:
        aodv: <default("Aodv")> like IApp {
            @display("p=825,226");
        }
    connections:
        aodv.socketOut --> at.in++;
        aodv.socketIn <-- at.out++;
}
